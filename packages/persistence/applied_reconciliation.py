"""Commit provenance beside a caller-owned canonical transition, never apply it.

Required readers authenticate same-database retained references under the account
fence. Independent venue observations must first be captured in this database.
No provider calls, object decoding, accounting or comparison occurs under a lock.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Literal, Protocol

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.reconciliation_persistence_contracts import (
    COMMIT_SCHEMA,
    MAX_COMMIT_BYTES,
    ReconciliationCommit,
    ReconciliationCommitReceipt,
    ReconciliationRetentionRead,
    ReconciliationSourceManifest,
    ResolvedReconciliationCommit,
)
from packages.domain.research_job_contracts import ObjectRef, ResearchRecordCodec
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    lock_account_capacity_serialization,
)
from packages.persistence.applied_reconciliation_schema import (
    applied_reconciliation_commits as commits,
)
from packages.persistence.durable_journal import PreparedJournalAppend, SqlDurableJournal


class AppliedReconciliationConflict(ValueError):
    """Immutable provenance/current fenced account bindings differ."""


class ReconciliationCommitResolver(Protocol):
    def resolve(self, commit: ReconciliationCommit) -> ResolvedReconciliationCommit:
        """Decode and validate immutable source/transition/comparison outside SQL."""
        ...


class ReconciliationTransactionReader(Protocol):
    def read_in_transaction(
        self,
        connection: Connection,
        *,
        transition: CanonicalAccountTransitionRef,
        sources: ReconciliationSourceManifest,
        objects: tuple[ObjectRef, ...],
        reconciliation_key: JournalKey,
        reconciliation_receipt: ReconciliationCommitReceipt,
        fence_receipt: AccountFenceReceipt,
    ) -> ReconciliationRetentionRead:
        """Return actual bounded retained metadata and seven current account heads.

        Must authenticate all supplied objects/records and original application
        receipt times against coordinator-retained rows, including nonbroker
        timestamps that AccountingState cannot intrinsically reconstruct. No
        independent database or heavy object/codec replay may run in this call.
        """
        ...


@dataclass(frozen=True, slots=True)
class ReconciliationCommitSnapshot:
    scope: ReconciliationScope
    row: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ResolvedReconciliationSnapshot:
    """Detached validated values; the original rows must still be rechecked.

    Ownership catches ordinary mixing/mutation, not arbitrary Python callers.
    Concrete source and canonical-transition authentication remain required.
    """

    snapshot: ReconciliationCommitSnapshot
    receipt: ReconciliationCommitReceipt
    resolved: ResolvedReconciliationCommit
    row_values: Mapping[str, Any]
    _owner: object
    _validated_values: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class PreparedReconciliationCommit:
    resolved: ResolvedReconciliationCommit
    journal: PreparedJournalAppend
    receipt: ReconciliationCommitReceipt
    payload: bytes
    previous: ResolvedReconciliationSnapshot | None
    row_values: Mapping[str, Any]
    _owner: object
    _validated_values: tuple[object, ...]


def reconciliation_journal_key(scope: ReconciliationScope) -> JournalKey:
    """A provenance-only stream inside the shared journal, one record per round."""
    scope.__post_init__()
    environment: Literal["synthetic", "sandbox", "production"] = (
        "synthetic"
        if scope.source_class == "stateful_simulation"
        else "sandbox"
        if scope.environment == "sandbox"
        else "production"
    )
    return JournalKey(
        "coordinator",
        "reconciliation-" + scope.semantic_sha256,
        scope.account_id,
        scope.provider_id,
        environment,
        scope.semantic_sha256,
    )


def _columns(connection: Connection) -> tuple[Any, ...]:
    result = []
    for column in commits.c:
        value: Any
        if isinstance(column.type, sa.String):
            if column.type.length is None:
                raise AppliedReconciliationConflict("UNBOUNDED_INDEX_COLUMN")
            value = sa.func.substr(column, 1, column.type.length + 1)
        elif isinstance(column.type, sa.LargeBinary):
            value = sa.func.substr(column, 1, MAX_COMMIT_BYTES + 1)
        else:
            value = (
                sa.case((sa.func.typeof(column) == "integer", column), else_=None)
                if connection.dialect.name == "sqlite"
                else column
            )
        result.append(value.label(column.name))
    return tuple(result)


class SqlAppliedReconciliation:
    def __init__(
        self,
        engine: Engine,
        *,
        coordinator: SqlAccountCoordinator,
        journal: SqlDurableJournal,
        codec: ResearchRecordCodec,
        evidence: ReconciliationCommitResolver,
        reader: ReconciliationTransactionReader,
    ) -> None:
        if type(coordinator) is not SqlAccountCoordinator or type(journal) is not SqlDurableJournal:
            raise AppliedReconciliationConflict("EXACT_COORDINATOR_AND_JOURNAL_REQUIRED")
        if engine.dialect.name not in ("sqlite", "postgresql"):
            raise AppliedReconciliationConflict("DIALECT_UNSUPPORTED")
        self.engine, self.coordinator, self.journal, self.codec = (
            engine,
            coordinator,
            journal,
            codec,
        )
        self.evidence, self.reader = evidence, reader
        self._owner = object()

    def prepare(
        self,
        commit: ReconciliationCommit,
        *,
        expected_head: JournalHead,
        previous: ResolvedReconciliationSnapshot | None,
    ) -> PreparedReconciliationCommit:
        """Resolve before SQL; bind the original prior receipt for this command.

        A historical retry uses its original predecessor, never today's head.
        ``previous=None`` is valid only for genesis, which commit rechecks.
        """
        resolved = self.evidence.resolve(commit)
        if type(resolved) is not ResolvedReconciliationCommit or resolved.commit != commit:
            raise AppliedReconciliationConflict("RESOLVED_COMMIT_MISMATCH")
        if previous is not None:
            self._resolved(previous)
        prior = None if previous is None else previous.receipt
        key = reconciliation_journal_key(commit.scope)
        if (
            (prior is not None and prior.commit.scope != commit.scope)
            or commit.previous_commit_sha256
            != (None if prior is None else prior.commit.semantic_sha256)
            or expected_head != (empty_head(key) if prior is None else prior.journal.committed_head)
        ):
            raise AppliedReconciliationConflict("PREPARED_RECONCILIATION_PREFIX_MISMATCH")
        previous_result = resolved.applications.previous_result
        if (previous_result is None) != (prior is None) or (
            prior is not None
            and previous_result is not None
            and previous_result.semantic_sha256 != prior.commit.result.semantic_sha256
        ):
            raise AppliedReconciliationConflict("PREVIOUS_RESULT_REFERENCE_MISMATCH")
        payload = self.codec.encode_record(commit)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_COMMIT_BYTES:
            raise AppliedReconciliationConflict("COMPACT_COMMIT_LIMIT")
        prepared = self.journal.prepare_append(
            key,
            JournalAppend(
                commit.command_id,
                commit.semantic_sha256,
                expected_head,
                (JournalRecord(commit.semantic_sha256, COMMIT_SCHEMA, payload),),
            ),
        )
        receipt = ReconciliationCommitReceipt(
            commit, prepared.receipt.committed_head.sequence, key, prepared.receipt
        )
        encoded = self.codec.encode_record(receipt)
        if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_COMMIT_BYTES:
            raise AppliedReconciliationConflict("COMPACT_RECEIPT_LIMIT")
        if self.codec.decode_record(encoded, ReconciliationCommitReceipt) != receipt:
            raise AppliedReconciliationConflict("COMPACT_RECEIPT_CODEC_MISMATCH")
        row_values = MappingProxyType(self._values(receipt, encoded))
        values = (resolved, prepared, receipt, encoded, previous, row_values)
        return PreparedReconciliationCommit(*values, self._owner, values)

    def _connection(self, connection: Connection) -> None:
        if connection.engine is not self.engine or not connection.in_transaction():
            raise AppliedReconciliationConflict("SAME_ENGINE_ACTIVE_TRANSACTION_REQUIRED")
        if (
            connection.dialect.name == "sqlite"
            and getattr(connection.connection.driver_connection, "in_transaction", False)
            is not True
        ):
            raise AppliedReconciliationConflict("SQLITE_EXPLICIT_TRANSACTION_REQUIRED")
        if connection.dialect.name == "postgresql" and connection.get_isolation_level() not in (
            "REPEATABLE READ",
            "SERIALIZABLE",
        ):
            raise AppliedReconciliationConflict("REPEATABLE_SNAPSHOT_REQUIRED")

    def _capture(
        self,
        connection: Connection,
        scope: ReconciliationScope,
        *,
        command_id: str | None,
    ) -> ReconciliationCommitSnapshot | None:
        self._connection(connection)
        statement = sa.select(*_columns(connection)).where(
            commits.c.scope_sha256 == scope.semantic_sha256
        )
        statement = (
            statement.order_by(commits.c.sequence.desc()).limit(1)
            if command_id is None
            else statement.where(commits.c.command_id == command_id)
        )
        row = connection.execute(statement).mappings().one_or_none()
        return (
            None
            if row is None
            else ReconciliationCommitSnapshot(scope, MappingProxyType(dict(row)))
        )

    def capture_current_in_transaction(
        self,
        connection: Connection,
        *,
        scope: ReconciliationScope,
    ) -> ReconciliationCommitSnapshot | None:
        return self._capture(connection, scope, command_id=None)

    def capture_commit_in_transaction(
        self,
        connection: Connection,
        *,
        scope: ReconciliationScope,
        command_id: str,
    ) -> ReconciliationCommitSnapshot | None:
        return self._capture(connection, scope, command_id=command_id)

    def capture_page_in_transaction(
        self,
        connection: Connection,
        *,
        through: ResolvedReconciliationSnapshot,
        after: ResolvedReconciliationSnapshot | None = None,
        limit: int = 100,
    ) -> tuple[ReconciliationCommitSnapshot, ...]:
        """Capture a fixed immutable prefix, at most 128 compact metadata rows."""
        self._connection(connection)
        if type(limit) is not int or not 1 <= limit <= 128:
            raise AppliedReconciliationConflict("HISTORY_PAGE_REQUEST_INVALID")
        self._resolved(through)
        if after is not None:
            self._resolved(after)
        scope = through.receipt.commit.scope
        end = through.receipt.sequence
        start = 0 if after is None else after.receipt.sequence
        if after is not None and (after.receipt.commit.scope != scope or start > end):
            raise AppliedReconciliationConflict("HISTORY_PAGE_PREFIX_INVALID")
        for anchor in (after, through):
            if anchor is not None:
                row = self._capture(connection, scope, command_id=anchor.receipt.commit.command_id)
                if row != anchor.snapshot:
                    raise AppliedReconciliationConflict("HISTORY_PAGE_ANCHOR_CHANGED")
        rows = tuple(
            ReconciliationCommitSnapshot(scope, MappingProxyType(dict(row)))
            for row in connection.execute(
                sa.select(*_columns(connection))
                .where(
                    commits.c.scope_sha256 == scope.semantic_sha256,
                    commits.c.sequence > start,
                    commits.c.sequence <= end,
                )
                .order_by(commits.c.sequence)
                .limit(limit)
            ).mappings()
        )
        expected_count = min(limit, end - start)
        if tuple(row.row["sequence"] for row in rows) != tuple(
            range(start + 1, start + expected_count + 1)
        ):
            raise AppliedReconciliationConflict("HISTORY_PAGE_INCOMPLETE")
        previous = None if after is None else after.receipt.commit.semantic_sha256
        for row in rows:
            if row.row["previous_commit_sha256"] != previous:
                raise AppliedReconciliationConflict("HISTORY_PAGE_CHAIN_CONFLICT")
            previous = row.row["commit_sha256"]
        return rows

    @staticmethod
    def _values(receipt: ReconciliationCommitReceipt, payload: bytes) -> dict[str, Any]:
        return dict(
            scope_sha256=receipt.commit.scope.semantic_sha256,
            command_id=receipt.commit.command_id,
            sequence=receipt.sequence,
            commit_sha256=receipt.commit.semantic_sha256,
            previous_commit_sha256=receipt.commit.previous_commit_sha256,
            journal_key_sha256=receipt.journal_key.semantic_sha256,
            journal_command_id=receipt.journal.command_id,
            journal_receipt_sha256=receipt.journal.semantic_sha256,
            first_journal_sequence=receipt.journal.previous_head.sequence + 1,
            last_journal_sequence=receipt.journal.committed_head.sequence,
            canonical_payload=payload,
        )

    def _decode(self, snapshot: ReconciliationCommitSnapshot) -> ReconciliationCommitReceipt:
        try:
            for column in commits.c:
                value = snapshot.row[column.name]
                if value is None and column.nullable:
                    continue
                if isinstance(column.type, sa.String):
                    if (
                        type(value) is not str
                        or column.type.length is None
                        or not 0 < len(value) <= column.type.length
                    ):
                        raise ValueError("text")
                elif isinstance(column.type, sa.LargeBinary):
                    if type(value) is not bytes or not 0 < len(value) <= MAX_COMMIT_BYTES:
                        raise ValueError("bytes")
                elif type(value) is not int or not 1 <= value <= 2**63 - 1:
                    raise ValueError("integer")
            payload = snapshot.row["canonical_payload"]
            receipt = self.codec.decode_record(payload, ReconciliationCommitReceipt)
            if (
                type(receipt) is not ReconciliationCommitReceipt
                or self.codec.encode_record(receipt) != payload
            ):
                raise ValueError("canonical")
            if (
                receipt.commit.scope != snapshot.scope
                or self._values(receipt, payload) != snapshot.row
            ):
                raise ValueError("mirrors")
            if receipt.journal_key != reconciliation_journal_key(snapshot.scope) or (
                receipt.journal.record_hashes
                != (sha256(self.codec.encode_record(receipt.commit)).hexdigest(),)
            ):
                raise ValueError("journal")
            return receipt
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise AppliedReconciliationConflict("RETAINED_COMMIT_INVALID") from None

    def resolve_snapshot(
        self, snapshot: ReconciliationCommitSnapshot
    ) -> ResolvedReconciliationSnapshot:
        """Heavy decoding/recomparison is detached. Callers must recheck before use."""
        receipt = self._decode(snapshot)
        resolved = self.evidence.resolve(receipt.commit)
        if type(resolved) is not ResolvedReconciliationCommit or resolved.commit != receipt.commit:
            raise AppliedReconciliationConflict("RESOLVED_COMMIT_MISMATCH")
        # Retain detached immutable row copies, even when the caller supplied a mapping.
        row_values = MappingProxyType(self._values(receipt, snapshot.row["canonical_payload"]))
        snapshot = ReconciliationCommitSnapshot(snapshot.scope, row_values)
        values = (snapshot, receipt, resolved, row_values)
        return ResolvedReconciliationSnapshot(*values, self._owner, values)

    def _resolved(self, value: ResolvedReconciliationSnapshot) -> None:
        if type(value) is not ResolvedReconciliationSnapshot or value._owner is not self._owner:
            raise AppliedReconciliationConflict("OWNED_RESOLVED_SNAPSHOT_REQUIRED")
        if (
            value.snapshot,
            value.receipt,
            value.resolved,
            value.row_values,
        ) != value._validated_values:
            raise AppliedReconciliationConflict("RESOLVED_SNAPSHOT_CHANGED")

    def recheck_snapshot_in_transaction(
        self,
        connection: Connection,
        *,
        resolved: ResolvedReconciliationSnapshot,
        fence: AccountFence,
    ) -> ReconciliationRetentionRead:
        """Reauthenticate retained closure; current risk eligibility remains B's check."""
        self._connection(connection)
        self._resolved(resolved)
        snapshot, receipt = resolved.snapshot, resolved.receipt
        current = self._capture(connection, snapshot.scope, command_id=snapshot.row["command_id"])
        if current != snapshot:
            raise AppliedReconciliationConflict("RETAINED_SNAPSHOT_CHANGED")
        if fence.account_id != snapshot.scope.account_id:
            raise AppliedReconciliationConflict("RESOLVED_SNAPSHOT_SCOPE_MISMATCH")
        lock_account_capacity_serialization(connection, snapshot.scope.account_id)
        checked = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        result = self._retention(connection, resolved.resolved, receipt, checked, historical=True)
        self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        return result

    def _retention(
        self,
        connection: Connection,
        resolved: ResolvedReconciliationCommit,
        receipt: ReconciliationCommitReceipt,
        fence_receipt: AccountFenceReceipt,
        *,
        historical: bool,
    ) -> ReconciliationRetentionRead:
        observed = self.reader.read_in_transaction(
            connection,
            transition=resolved.commit.canonical_transition_ref,
            sources=resolved.sources,
            objects=resolved.retained_objects,
            fence_receipt=fence_receipt,
            reconciliation_key=receipt.journal_key,
            reconciliation_receipt=receipt,
        )
        if type(observed) is not ReconciliationRetentionRead or (
            observed.transition != resolved.commit.canonical_transition_ref
            or observed.sources != resolved.sources
            or observed.objects != resolved.retained_objects
            or observed.capture_binding != resolved.commit.capture_binding
        ):
            raise AppliedReconciliationConflict("RETAINED_SOURCE_TRANSITION_METADATA_MISMATCH")
        if observed.journal_receipt != (receipt.journal if historical else None):
            raise AppliedReconciliationConflict("RETAINED_JOURNAL_RECEIPT_MISMATCH")
        if not historical and (
            observed.current_heads != resolved.commit.resulting_heads
            or observed.current_heads.lease_generation != fence_receipt.fence.fencing_generation
            or observed.journal_head != receipt.journal.previous_head
            or resolved.result.completed_at > fence_receipt.validated_at
            or resolved.commit.canonical_transition_ref.applied_at > fence_receipt.validated_at
        ):
            raise AppliedReconciliationConflict("CURRENT_ACCOUNT_HEADS_MISMATCH")
        return observed

    def commit_in_transaction(
        self,
        connection: Connection,
        *,
        prepared: PreparedReconciliationCommit,
        fence: AccountFence,
    ) -> ReconciliationCommitReceipt:
        """Any failure must abort the caller's complete canonical account operation."""
        self._connection(connection)
        if type(prepared) is not PreparedReconciliationCommit or prepared._owner is not self._owner:
            raise AppliedReconciliationConflict("OWNED_PREPARATION_REQUIRED")
        if (
            prepared.resolved,
            prepared.journal,
            prepared.receipt,
            prepared.payload,
            prepared.previous,
            prepared.row_values,
        ) != prepared._validated_values:
            raise AppliedReconciliationConflict("PREPARATION_CHANGED")
        commit = prepared.resolved.commit
        if type(fence) is not AccountFence or fence.account_id != commit.scope.account_id:
            raise AppliedReconciliationConflict("ACCOUNT_FENCE_SCOPE_MISMATCH")
        lock_account_capacity_serialization(connection, commit.scope.account_id)
        try:
            with connection.begin_nested():
                fence_receipt = self.coordinator.revalidate_for_commit_in_transaction(
                    connection, fence
                )
                old = self._capture(connection, commit.scope, command_id=commit.command_id)
                if old is not None:
                    if old.row != prepared.row_values:
                        raise AppliedReconciliationConflict("IMMUTABLE_RETRY_CONFLICT")
                    self._retention(
                        connection,
                        prepared.resolved,
                        prepared.receipt,
                        fence_receipt,
                        historical=True,
                    )
                    if (
                        self.journal.append_in_transaction(connection, prepared.journal)
                        != prepared.receipt.journal
                    ):
                        raise AppliedReconciliationConflict("RETAINED_JOURNAL_CONFLICT")
                    self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
                    return prepared.receipt
                latest = self._capture(connection, commit.scope, command_id=None)
                expected_prior = None if prepared.previous is None else prepared.previous.snapshot
                if latest != expected_prior:
                    raise AppliedReconciliationConflict("CURRENT_RECONCILIATION_PREFIX_MISMATCH")
                self._retention(
                    connection, prepared.resolved, prepared.receipt, fence_receipt, historical=False
                )
                actual = self.journal.append_in_transaction(connection, prepared.journal)
                if actual != prepared.receipt.journal:
                    raise AppliedReconciliationConflict("PREPARED_JOURNAL_CONFLICT")
                insertion = sqlite_insert if connection.dialect.name == "sqlite" else pg_insert
                inserted = connection.execute(
                    insertion(commits)
                    .values(**prepared.row_values)
                    .on_conflict_do_nothing()
                    .returning(commits.c.commit_sha256)
                ).scalar_one_or_none()
                if inserted != commit.semantic_sha256:
                    raise AppliedReconciliationConflict("COMMIT_INDEX_INSERT_CONFLICT")
                stored = self._capture(connection, commit.scope, command_id=commit.command_id)
                if stored is None or stored.row != prepared.row_values:
                    raise AppliedReconciliationConflict("COMMIT_INDEX_READBACK_CONFLICT")
                self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
                return prepared.receipt
        except IntegrityError:
            raise AppliedReconciliationConflict("COMMIT_INDEX_SQL_CONFLICT") from None
