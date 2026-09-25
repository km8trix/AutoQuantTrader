"""Detached checkpoint preparation and bounded fenced metadata publication.

The mandatory composer authenticates retained inputs and couples actual risk
admissions. This store owns no financial reducer or exposure permission.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from datetime import datetime
from hashlib import sha256
from threading import Event, Lock, Thread, current_thread
from types import MappingProxyType, TracebackType
from typing import Any, Protocol, TypeVar, cast
from weakref import WeakValueDictionary, finalize

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from packages.application.continuous_account_transition import (
    ContinuousAccountTransitionPreparer,
    PreparedContinuousTransition,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt, AccountLease
from packages.domain.accounting_contracts import Commitment
from packages.domain.canonical import canonical_json_bytes
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    CONTINUOUS_REQUEST_SCHEMA,
    CONTINUOUS_RUNTIME_ACTION_SCHEMA,
    MAX_CONTINUOUS_COMMIT_BYTES,
    MAX_CONTINUOUS_OBJECT_BYTES,
    MAX_CONTINUOUS_PAGE,
    ContinuousAccountCommit,
    ContinuousAccountReceipt,
    ContinuousAccountRecord,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
    ContinuousFenceReference,
)
from packages.domain.continuous_quote_contracts import CONTINUOUS_QUOTE_CLOSURE_SCHEMA
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    _rollback_failed_write,
    account_lease_from_row,
    lock_account_capacity_serialization,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_commits as commits,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_heads as heads,
)
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.daily_runtime_risk import (
    PreparedDailyAdmission,
    PreparedDailyAttemptMutation,
    PreparedDailyObservedHolds,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    PreparedJournalAppend,
    ResolvedJournalRead,
    SqlDurableJournal,
)
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import phase2_account_leases

OwnedT = TypeVar("OwnedT")
_EVENT_IS_SET = Event.is_set


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousComposition:
    expected_heads: ReconciliationHeads
    resulting_heads: ReconciliationHeads
    source_evidence: ContinuousEvidenceRef
    decision_evidence: ContinuousEvidenceRef
    installed_commitments: tuple[Commitment, ...]
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)
    valid_until: datetime | None = None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContinuousCompositionSnapshot:
    commit_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContinuousCompositionPlan:
    commit_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousComposition:
    commit_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ContinuousAccountSnapshot:
    scope: ContinuousAccountScope
    row: Mapping[str, Any]
    journal: JournalReadSnapshot
    composition: ContinuousCompositionSnapshot
    lease: Mapping[str, Any]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousAccount:
    snapshot: ContinuousAccountSnapshot
    receipt: ContinuousAccountReceipt
    checkpoint: CausalEngineCheckpoint
    request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction
    journal: ResolvedJournalRead
    composition: ResolvedContinuousComposition
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ContinuousIndexSnapshot:
    scope: ContinuousAccountScope
    row: Mapping[str, Any]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousIndex:
    snapshot: ContinuousIndexSnapshot
    receipt: ContinuousAccountReceipt
    composition_plan: ContinuousCompositionPlan | None
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContinuousReferenceSnapshot:
    """Original publication metadata only; no decoded checkpoint or composition."""

    current: ContinuousIndexSnapshot
    lease: Mapping[str, Any]
    journal: JournalReadSnapshot
    previous: ContinuousIndexSnapshot | None
    previous_lease: Mapping[str, Any] | None
    previous_journal: JournalReadSnapshot | None
    source_lease_sha256: str | None = None
    source_lease: Mapping[str, Any] | None = None


def _reference_fingerprint(
    snapshot: ContinuousReferenceSnapshot,
    journal: ResolvedJournalRead,
    prior_journal: ResolvedJournalRead | None,
) -> str:
    """Hash the original fully detached metadata anew on every outside-SQL call."""
    return sha256(
        canonical_json_bytes(detached_journal_value((snapshot, journal, prior_journal)))
    ).hexdigest()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousReference:
    snapshot: ContinuousReferenceSnapshot
    receipt: ContinuousAccountReceipt
    previous_receipt: ContinuousAccountReceipt | None
    journal: ResolvedJournalRead
    previous_journal: ResolvedJournalRead | None
    source_lease: AccountLease | None
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousCommit:
    commit: ContinuousAccountCommit
    payload: bytes
    journal: PreparedJournalAppend
    composition: PreparedContinuousComposition
    previous: ResolvedContinuousAccount | None
    row_values: Mapping[str, Any]
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _PendingContinuousPublication:
    prepared: PreparedContinuousCommit
    receipt: ContinuousAccountReceipt
    fence: AccountFence
    fence_sha256: str
    index: ContinuousIndexSnapshot
    journal: JournalReadSnapshot
    lease: Mapping[str, Any]


class ContinuousCommitComposer(Protocol):
    """Required producer, with per-instance weak identity/fingerprint ownership.

    prepare/resolve/require methods run outside SQL. Capture returns copied,
    bounded rows; recheck/apply use only bounded SQL and lightweight ownership
    checks. Historical rechecks authenticate original evidence, never refresh
    decisions, apply admissions or make a retry deliverable.
    """

    def prepare(
        self,
        transition: PreparedContinuousTransition,
        *,
        previous: ResolvedContinuousAccount | None,
        source_evidence: ContinuousEvidenceRef,
        admissions: tuple[PreparedDailyAdmission, ...],
        observed_holds: PreparedDailyObservedHolds | None = None,
        attempts: PreparedDailyAttemptMutation | None = None,
    ) -> PreparedContinuousComposition: ...

    def require_prepared(self, value: PreparedContinuousComposition) -> None: ...

    def prepare_capture(
        self, commit: ContinuousAccountCommit, *, previous: ResolvedContinuousAccount | None
    ) -> ContinuousCompositionPlan:
        """Discover exact retained object/source references outside SQL."""
        ...

    def capture_in_transaction(
        self,
        connection: Connection,
        *,
        commit: ContinuousAccountCommit,
        plan: ContinuousCompositionPlan,
    ) -> ContinuousCompositionSnapshot: ...

    def resolve(
        self,
        snapshot: ContinuousCompositionSnapshot,
        *,
        commit: ContinuousAccountCommit,
        checkpoint: CausalEngineCheckpoint,
        request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction,
        previous: ResolvedContinuousAccount | None,
    ) -> ResolvedContinuousComposition: ...

    def require_resolved(self, value: ResolvedContinuousComposition) -> None: ...

    def recheck_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedContinuousComposition,
        *,
        require_current: bool,
    ) -> None: ...

    def apply_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedContinuousComposition,
        *,
        fence: AccountFence,
        fence_receipt: AccountFenceReceipt,
    ) -> ReconciliationHeads: ...


class ContinuousAccountConflict(ValueError):
    """Bounded retained account bindings or current fenced heads differ."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _ContinuousStopScope:
    account: SqlContinuousAccount = field(repr=False)
    stop_event: Event = field(repr=False)
    thread: Thread = field(repr=False)
    seal: object = field(repr=False)

    def __enter__(self) -> None:
        self.account._enter_cooperative_stop_scope(self)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.account._exit_cooperative_stop_scope(self)


def continuous_account_journal_key(scope: ContinuousAccountScope) -> JournalKey:
    # This is the coordinator state stream, never a relabelled provider stream.
    return JournalKey(
        "coordinator",
        scope.stream_id,
        scope.account_id,
        "continuous-account/1",
        "synthetic",
        scope.semantic_sha256,
    )


def _columns(connection: Connection, table: sa.Table) -> tuple[Any, ...]:
    result = []
    for column in table.c:
        value: Any
        if isinstance(column.type, sa.String) and column.type.length is not None:
            value = sa.func.substr(column, 1, column.type.length + 1)
        elif isinstance(column.type, sa.LargeBinary):
            value = sa.func.substr(column, 1, MAX_CONTINUOUS_COMMIT_BYTES + 1)
        else:
            value = (
                sa.case((sa.func.typeof(column) == "integer", column), else_=None)
                if connection.dialect.name == "sqlite"
                else column
            )
        result.append(value.label(column.name))
    return tuple(result)


def _validate_row(row: Mapping[str, Any], table: sa.Table) -> None:
    for column in table.c:
        value = row[column.name]
        if value is None and column.nullable:
            continue
        if isinstance(column.type, sa.String):
            valid = type(value) is str and 0 < len(value) <= (column.type.length or 0)
        elif isinstance(column.type, sa.LargeBinary):
            valid = type(value) is bytes and 0 < len(value) <= MAX_CONTINUOUS_COMMIT_BYTES
        else:
            valid = type(value) is int and 1 <= value <= 2**63 - 1
        if not valid:
            raise ContinuousAccountConflict("CONTINUOUS_INDEX_TYPE_OR_BOUND")


def _capture_lease(connection: Connection, lease_sha256: str) -> Mapping[str, Any]:
    selected = []
    for column in phase2_account_leases.c:
        value: Any
        if isinstance(column.type, sa.DateTime):
            value = sa.func.substr(sa.cast(column, sa.String), 1, 65)
        elif isinstance(column.type, sa.String):
            value = sa.func.substr(
                column, 1, (column.type.length or MAX_CONTINUOUS_COMMIT_BYTES) + 1
            )
        else:
            value = (
                sa.case((sa.func.typeof(column) == "integer", column), else_=None)
                if connection.dialect.name == "sqlite"
                else column
            )
        selected.append(value.label(column.name))
    row = (
        connection.execute(
            sa.select(*selected).where(
                phase2_account_leases.c.lease_sha256 == lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ContinuousAccountConflict("CONTINUOUS_RETAINED_LEASE_MISSING")
    return MappingProxyType(dict(row))


def _decode_lease_row(row: Mapping[str, Any]) -> AccountLease:
    try:
        values = dict(row)
        for column in phase2_account_leases.c:
            value = values[column.name]
            if value is None and column.nullable:
                continue
            if isinstance(column.type, sa.DateTime):
                if type(value) is not str or len(value) > 64:
                    raise ValueError("lease timestamp")
                values[column.name] = as_aware_utc(datetime.fromisoformat(value))
            elif isinstance(column.type, sa.String):
                if type(value) is not str or not 0 < len(value) <= (
                    column.type.length or MAX_CONTINUOUS_COMMIT_BYTES
                ):
                    raise ValueError("lease text")
            elif type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise ValueError("lease integer")
        lease = account_lease_from_row(values)
        return lease
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ContinuousAccountConflict("CONTINUOUS_RETAINED_LEASE_INVALID") from None


def _validate_lease(row: Mapping[str, Any], receipt: ContinuousAccountReceipt) -> None:
    try:
        lease = _decode_lease_row(row)
        ref = receipt.fence_reference
        if (
            lease.semantic_sha256 != ref.lease_sha256
            or lease.account_id != receipt.commit.scope.account_id
            or lease.owner_id != ref.owner_id
            or lease.lease_id != ref.lease_id
            or lease.fencing_generation != ref.fencing_generation
            or lease.policy_sha256 != ref.policy_sha256
            or lease.expires_at != ref.valid_until
            or not lease.heartbeat_at <= receipt.recorded_at < lease.expires_at
        ):
            raise ValueError("lease bindings")
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ContinuousAccountConflict("CONTINUOUS_RETAINED_LEASE_INVALID") from None


class SqlContinuousAccount:
    def __init__(
        self,
        engine: Engine,
        *,
        coordinator: SqlAccountCoordinator,
        journal: SqlDurableJournal,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        preparer: ContinuousAccountTransitionPreparer,
        composer: ContinuousCommitComposer,
    ) -> None:
        if (
            type(coordinator) is not SqlAccountCoordinator
            or type(journal) is not SqlDurableJournal
            or type(preparer) is not ContinuousAccountTransitionPreparer
            or engine.dialect.name not in ("sqlite", "postgresql")
        ):
            raise ContinuousAccountConflict("EXACT_CONTINUOUS_DEPENDENCIES_REQUIRED")
        self.engine, self.coordinator, self.journal = engine, coordinator, journal
        self.artifacts, self.codec, self.preparer, self.composer = (
            artifacts,
            codec,
            preparer,
            composer,
        )
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._owned_fields: dict[int, tuple[object, ...]] = {}
        self._metadata_fingerprints: dict[int, str] = {}
        self._write_connections: dict[int, tuple[Connection, object]] = {}
        self._pending_publications: dict[int, list[_PendingContinuousPublication]] = {}
        # Only authenticated immutable lineage is retained here. An ancestor
        # never makes a freshness, current-head or reconciliation-status claim.
        self._venue_ancestors: dict[int, ResolvedContinuousAccount] = {}
        self._quote_ancestors: dict[int, ResolvedContinuousAccount] = {}
        self._reference_fingerprints: dict[int, str] = {}
        self._reference_captures: WeakValueDictionary[int, ContinuousReferenceSnapshot] = (
            WeakValueDictionary()
        )
        self._reference_capture_fields: dict[int, tuple[object, ...]] = {}
        self._cooperative_stop_lock = Lock()
        self._cooperative_stop_latched = False
        self._cooperative_stop_scope: _ContinuousStopScope | None = None
        self._cooperative_stop_owned: WeakValueDictionary[int, _ContinuousStopScope] = (
            WeakValueDictionary()
        )
        self._cooperative_stop_fields: dict[int, tuple[object, ...]] = {}
        self._cooperative_stop_used: set[int] = set()
        self._cooperative_writes: dict[object, _ContinuousStopScope | None] = {}

    def cooperative_stop_scope(self, stop_event: Event) -> _ContinuousStopScope:
        """Bind one operation's exact Event to this thread, with permanent stop denial.

        A sampled stop prevents a subsequent COMMIT; a signal arriving between
        the final sample and COMMIT can race that COMMIT. This is a cooperative
        in-process check, not an atomic cross-process stop/SQL operation.
        """
        if type(stop_event) is not Event:
            raise ContinuousAccountConflict("EXACT_CONTINUOUS_STOP_EVENT_REQUIRED")
        with self._cooperative_stop_lock:
            if self._cooperative_stop_latched:
                raise ContinuousAccountConflict("CONTINUOUS_COOPERATIVE_STOPPED")
            scope = _ContinuousStopScope(self, stop_event, current_thread(), self._seal)
            key = id(scope)
            self._cooperative_stop_owned[key] = scope
            self._cooperative_stop_fields[key] = (
                scope.account,
                scope.stop_event,
                scope.thread,
                scope.seal,
            )
            finalize(scope, self._cooperative_stop_fields.pop, key, None)
            finalize(scope, self._cooperative_stop_used.discard, key)
            return scope

    def _require_cooperative_stop_scope(self, scope: _ContinuousStopScope) -> None:
        # Called only while holding the internal stop lock. Ownership is local
        # identity, never an Event's truthiness or a caller-supplied callback.
        if (
            type(scope) is not _ContinuousStopScope
            or self._cooperative_stop_owned.get(id(scope)) is not scope
            or scope.account is not self
            or scope.seal is not self._seal
            or type(scope.stop_event) is not Event
            or any(
                actual is not original
                for actual, original in zip(
                    (scope.account, scope.stop_event, scope.thread, scope.seal),
                    self._cooperative_stop_fields.get(id(scope), ()),
                    strict=True,
                )
            )
        ):
            raise ContinuousAccountConflict("ORIGINAL_CONTINUOUS_STOP_SCOPE_REQUIRED")
        if scope.thread is not current_thread():
            raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_THREAD_CHANGED")

    def _sample_cooperative_stop(self, scope: _ContinuousStopScope) -> None:
        # Bypass any instance-level replacement method on the exact Event.
        stopped = _EVENT_IS_SET(scope.stop_event)
        if type(stopped) is not bool or stopped:
            self._cooperative_stop_latched = True

    def _enter_cooperative_stop_scope(self, scope: _ContinuousStopScope) -> None:
        with self._cooperative_stop_lock:
            self._require_cooperative_stop_scope(scope)
            if (
                id(scope) in self._cooperative_stop_used
                or self._cooperative_stop_scope is not None
                or self._cooperative_writes
            ):
                raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_CONFLICT")
            self._sample_cooperative_stop(scope)
            if self._cooperative_stop_latched:
                raise ContinuousAccountConflict("CONTINUOUS_COOPERATIVE_STOPPED")
            self._cooperative_stop_used.add(id(scope))
            self._cooperative_stop_scope = scope

    def _exit_cooperative_stop_scope(self, scope: _ContinuousStopScope) -> None:
        with self._cooperative_stop_lock:
            self._require_cooperative_stop_scope(scope)
            if self._cooperative_stop_scope is not scope:
                raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_CONFLICT")
            self._sample_cooperative_stop(scope)
            self._cooperative_stop_scope = None
            if self._cooperative_writes:
                self._cooperative_stop_latched = True
                raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_WRITE_ACTIVE")
            # Latch a stop without masking an exception from the operation.

    def _begin_cooperative_write(self) -> object:
        with self._cooperative_stop_lock:
            scope = self._cooperative_stop_scope
            if scope is not None:
                self._require_cooperative_stop_scope(scope)
                self._sample_cooperative_stop(scope)
                if self._cooperative_writes:
                    raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_WRITE_ACTIVE")
            if self._cooperative_stop_latched:
                raise ContinuousAccountConflict("CONTINUOUS_COOPERATIVE_STOPPED")
            token = object()
            self._cooperative_writes[token] = scope
            return token

    def _check_cooperative_write(self, token: object) -> None:
        with self._cooperative_stop_lock:
            if (
                token not in self._cooperative_writes
                or self._cooperative_writes[token] is not self._cooperative_stop_scope
            ):
                raise ContinuousAccountConflict("CONTINUOUS_STOP_SCOPE_CHANGED")
            scope = self._cooperative_writes[token]
            if scope is not None:
                self._require_cooperative_stop_scope(scope)
                self._sample_cooperative_stop(scope)
            if self._cooperative_stop_latched:
                raise ContinuousAccountConflict("CONTINUOUS_COOPERATIVE_STOPPED")

    def _finish_cooperative_write(self, token: object) -> None:
        with self._cooperative_stop_lock:
            self._cooperative_writes.pop(token, None)

    @contextmanager
    def write_transaction(self) -> Iterator[Connection]:
        """Caller-owned scope for all coupled writes, with actual write admission."""
        stop_token = self._begin_cooperative_write()
        try:
            with self.engine.connect() as original:
                connection = original
                if connection.dialect.name == "postgresql":
                    connection = connection.execution_options(isolation_level="REPEATABLE READ")
                    connection.begin()
                else:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                transaction = connection.get_transaction()
                assert transaction is not None
                self._write_connections[id(connection)] = (connection, transaction)
                self._pending_publications[id(connection)] = []
                try:
                    yield connection
                    self._check_cooperative_write(stop_token)
                    self._mutation_connection(connection)
                    self._validate_pending_publications(connection)
                    self._check_cooperative_write(stop_token)
                    connection.commit()
                except BaseException:
                    _rollback_failed_write(connection)
                    raise
                finally:
                    self._pending_publications.pop(id(connection), None)
                    self._write_connections.pop(id(connection), None)
        finally:
            self._finish_cooperative_write(stop_token)

    def _mutation_connection(self, connection: Connection) -> None:
        self._connection(connection)
        registered = self._write_connections.get(id(connection))
        if (
            registered is None
            or registered[0] is not connection
            or (registered[1] is not connection.get_transaction())
        ):
            raise ContinuousAccountConflict("OWNED_CONTINUOUS_WRITE_TRANSACTION_REQUIRED")

    def _revalidate_publication_fence(
        self, connection: Connection, publication: _PendingContinuousPublication
    ) -> None:
        self._require(publication.prepared, PreparedContinuousCommit)
        if publication.fence.semantic_sha256 != publication.fence_sha256:
            raise ContinuousAccountConflict("CONTINUOUS_PUBLICATION_FENCE_CHANGED")
        checked = self.coordinator.revalidate_for_commit_in_transaction(
            connection, publication.fence
        )
        deadline = publication.prepared.composition.valid_until
        if deadline is not None and checked.validated_at >= deadline:
            raise ContinuousAccountConflict("CONTINUOUS_PUBLICATION_DEADLINE_EXPIRED")

    def _recheck_publication(
        self,
        connection: Connection,
        publication: _PendingContinuousPublication,
        *,
        require_current: bool,
    ) -> ContinuousIndexSnapshot:
        self._require(publication.prepared, PreparedContinuousCommit)
        receipt = publication.receipt
        expected = publication.index
        if (
            receipt.commit is not publication.prepared.commit
            or (dict(publication.prepared.row_values) | self._receipt_values(receipt))
            != expected.row
        ):
            raise ContinuousAccountConflict("CONTINUOUS_ISSUED_RECEIPT_CHANGED")
        if (
            self._capture_row(connection, expected.scope, receipt.commit.transition.command_id)
            != expected
        ):
            raise ContinuousAccountConflict("CONTINUOUS_PUBLISHED_INDEX_CHANGED")
        if (
            require_current
            and self.capture_current_in_transaction(connection, scope=expected.scope) != expected
        ):
            raise ContinuousAccountConflict("CONTINUOUS_PUBLISHED_HEAD_CHANGED")
        if _capture_lease(connection, receipt.fence_reference.lease_sha256) != publication.lease:
            raise ContinuousAccountConflict("CONTINUOUS_PUBLISHED_LEASE_CHANGED")
        raw = self.journal.capture_in_transaction(
            connection, publication.journal.key, command_id=publication.journal.command_id
        )
        # Successful append already validated these exact bounded rows. Recheck
        # their bytes without decoding the newly written record under SQL.
        if require_current:
            unchanged = raw == publication.journal
        else:
            unchanged = (
                raw.requested_receipt == publication.journal.requested_receipt
                and not raw.empty_has_records
                and not raw.missing_receipt_has_entries
            )
        if not unchanged:
            raise ContinuousAccountConflict("CONTINUOUS_PUBLISHED_JOURNAL_CHANGED")
        return expected

    def _validate_pending_publications(self, connection: Connection) -> None:
        pending = self._pending_publications[id(connection)]
        latest = {item.index.scope.account_id: item for item in pending}
        for item in pending:
            self._recheck_publication(
                connection, item, require_current=latest[item.index.scope.account_id] is item
            )
        # Sample actual clocks after all coupled writes and metadata readbacks.
        # No codec, financial replay or caller callback occurs before COMMIT.
        for item in pending:
            self._revalidate_publication_fence(connection, item)

    def require_committed_in_transaction(
        self,
        connection: Connection,
        *,
        prepared: PreparedContinuousCommit,
        receipt: ContinuousAccountReceipt,
    ) -> ContinuousIndexSnapshot:
        """Authenticate this scope's exact issued publication before coupled writes.

        This readback does not COMMIT, encode records or grant delivery authority.
        The owning context repeats its checks immediately before the outer COMMIT.
        """
        self._mutation_connection(connection)
        self._require(prepared, PreparedContinuousCommit)
        publication = next(
            (
                item
                for item in self._pending_publications[id(connection)]
                if item.prepared is prepared and item.receipt is receipt
            ),
            None,
        )
        if publication is None:
            raise ContinuousAccountConflict("OWNED_CONTINUOUS_PUBLICATION_REQUIRED")
        result = self._recheck_publication(connection, publication, require_current=True)
        self._revalidate_publication_fence(connection, publication)
        return result

    @staticmethod
    def _metadata_fingerprint(value: Any) -> str:
        # Only compact metadata; never a checkpoint or an injected codec.
        if type(value) is PreparedContinuousCommit:
            return content_digest(
                (
                    value.commit,
                    value.payload,
                    value.composition.valid_until,
                    tuple((str(k), v) for k, v in value.row_values.items()),
                )
            )
        if type(value) is ResolvedContinuousAccount:
            return content_digest(
                (
                    value.receipt,
                    tuple((str(k), v) for k, v in value.snapshot.row.items()),
                    tuple((str(k), v) for k, v in value.snapshot.lease.items()),
                )
            )
        if type(value) is ResolvedContinuousReference:
            raw = value.snapshot
            return content_digest(
                (
                    value.receipt,
                    value.previous_receipt,
                    tuple((str(k), v) for k, v in raw.current.row.items()),
                    tuple((str(k), v) for k, v in raw.lease.items()),
                    None
                    if raw.previous is None
                    else tuple((str(k), v) for k, v in raw.previous.row.items()),
                    None
                    if raw.previous_lease is None
                    else tuple((str(k), v) for k, v in raw.previous_lease.items()),
                    raw.source_lease_sha256,
                    None
                    if raw.source_lease is None
                    else tuple((str(k), v) for k, v in raw.source_lease.items()),
                    value.source_lease,
                )
            )
        return content_digest(
            (value.receipt, tuple((str(k), v) for k, v in value.snapshot.row.items()))
        )

    def _own(self, value: OwnedT) -> OwnedT:
        self._owned[id(value)] = value
        self._owned_fields[id(value)] = tuple(
            getattr(value, f.name) for f in fields(cast(Any, value))
        )
        self._metadata_fingerprints[id(value)] = self._metadata_fingerprint(value)
        finalize(value, self._owned_fields.pop, id(value), None)
        finalize(value, self._metadata_fingerprints.pop, id(value), None)
        return value

    def _require(self, value: Any, expected: type[Any]) -> None:
        if (
            type(value) is not expected
            or value.seal is not self._seal
            or (self._owned.get(id(value)) is not value)
        ):
            raise ContinuousAccountConflict("OWNED_CONTINUOUS_VALUE_REQUIRED")
        original = self._owned_fields[id(value)]
        if (
            any(
                getattr(value, f.name) is not previous
                for f, previous in zip(
                    fields(cast(Any, value)),
                    original,
                    strict=True,
                )
            )
            or self._metadata_fingerprint(value) != self._metadata_fingerprints[id(value)]
        ):
            raise ContinuousAccountConflict("OWNED_CONTINUOUS_VALUE_CHANGED")

    def _connection(self, connection: Connection) -> None:
        if connection.engine is not self.engine or not connection.in_transaction():
            raise ContinuousAccountConflict("SAME_ENGINE_ACTIVE_TRANSACTION_REQUIRED")
        if connection.dialect.name == "sqlite" and (
            getattr(connection.connection.driver_connection, "in_transaction", False) is not True
        ):
            raise ContinuousAccountConflict("SQLITE_PHYSICAL_TRANSACTION_REQUIRED")
        if connection.dialect.name == "postgresql" and connection.get_isolation_level() not in (
            "REPEATABLE READ",
            "SERIALIZABLE",
        ):
            raise ContinuousAccountConflict("REPEATABLE_SNAPSHOT_REQUIRED")

    def _object(self, ref: ObjectRef) -> bytes:
        if ref.codec_version != "personal-record/1" or ref.byte_count > MAX_CONTINUOUS_OBJECT_BYTES:
            raise ContinuousAccountConflict("CONTINUOUS_OBJECT_TYPE_OR_BOUND")
        payload = self.artifacts.read(ref, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
        if (
            type(payload) is not bytes
            or len(payload) != ref.byte_count
            or (sha256(payload).hexdigest() != ref.object_sha256)
        ):
            raise ContinuousAccountConflict("CONTINUOUS_OBJECT_BYTES_DIFFER")
        return payload

    def _put(self, value: Any) -> ObjectRef:
        payload = self.codec.encode_record(value)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_CONTINUOUS_OBJECT_BYTES:
            raise ContinuousAccountConflict("CONTINUOUS_OBJECT_TYPE_OR_BOUND")
        if self.codec.decode_record(payload, type(value)) != value:
            raise ContinuousAccountConflict("CONTINUOUS_OBJECT_CODEC_DIFFERS")
        ref = self.artifacts.put(payload, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
        if (
            ref.codec_version != "personal-record/1"
            or ref.byte_count != len(payload)
            or (ref.object_sha256 != sha256(payload).hexdigest())
        ):
            raise ContinuousAccountConflict("CONTINUOUS_OBJECT_INSTALL_DIFFERS")
        return ref

    @staticmethod
    def _base_values(record: ContinuousAccountRecord, payload: bytes) -> dict[str, Any]:
        commit, journal = record.commit, record.journal
        return dict(
            account_id=commit.scope.account_id,
            command_id=commit.transition.command_id,
            scope_sha256=commit.scope.semantic_sha256,
            sequence=commit.sequence,
            commit_sha256=commit.semantic_sha256,
            previous_commit_sha256=commit.previous_commit_sha256,
            checkpoint_sha256=commit.transition.checkpoint_sha256,
            journal_key_sha256=journal.previous_head.key_sha256,
            journal_receipt_sha256=journal.semantic_sha256,
            canonical_payload=payload,
        )

    @staticmethod
    def _receipt_values(receipt: ContinuousAccountReceipt) -> dict[str, Any]:
        ref = receipt.fence_reference
        return dict(
            recorded_at=receipt.recorded_at.isoformat(),
            owner_id=ref.owner_id,
            lease_id=ref.lease_id,
            fencing_generation=ref.fencing_generation,
            lease_sha256=ref.lease_sha256,
            policy_sha256=ref.policy_sha256,
            valid_until=ref.valid_until.isoformat(),
            receipt_sha256=receipt.semantic_sha256,
        )

    @staticmethod
    def _head_values(row: Mapping[str, Any]) -> dict[str, Any]:
        return {column.name: row[column.name] for column in heads.c}

    def prepare(
        self,
        transition: PreparedContinuousTransition,
        *,
        scope: ContinuousAccountScope,
        previous: ResolvedContinuousAccount | None,
        source_evidence: ContinuousEvidenceRef,
        admissions: tuple[PreparedDailyAdmission, ...] = (),
        observed_holds: PreparedDailyObservedHolds | None = None,
        attempts: PreparedDailyAttemptMutation | None = None,
    ) -> PreparedContinuousCommit:
        """Retain actual engine objects outside SQL; exact retries use retry instead."""
        self.preparer.require_prepared(transition)
        if previous is not None:
            self._require(previous, ResolvedContinuousAccount)
            if (
                previous.checkpoint.semantic_sha256
                != previous.receipt.commit.transition.checkpoint_sha256
            ):
                raise ContinuousAccountConflict("OWNED_RESTORED_CHECKPOINT_CHANGED")
        cp = transition.checkpoint
        if type(cp.inputs) is not ContinuousEngineInputs or (
            cp.inputs.spec.account_id != scope.account_id
            or cp.inputs.spec.deployment_id != scope.stream_id
            or cp.inputs.spec.account_binding_sha256 != scope.account_binding_sha256
            or transition.disposition == "idempotent"
            or transition.previous_checkpoint_sha256
            != (None if previous is None else previous.checkpoint.semantic_sha256)
            or (previous is not None and previous.receipt.commit.scope != scope)
        ):
            raise ContinuousAccountConflict("CONTINUOUS_PREPARATION_SCOPE_OR_PREFIX_DIFFERS")
        composition = (
            self.composer.prepare(
                transition,
                previous=previous,
                source_evidence=source_evidence,
                admissions=admissions,
                observed_holds=observed_holds,
                attempts=attempts,
            )
            if attempts is not None
            else (
                self.composer.prepare(
                    transition,
                    previous=previous,
                    source_evidence=source_evidence,
                    admissions=admissions,
                )
                if observed_holds is None
                else self.composer.prepare(
                    transition,
                    previous=previous,
                    source_evidence=source_evidence,
                    admissions=admissions,
                    observed_holds=observed_holds,
                )
            )
        )
        self.composer.require_prepared(composition)
        if type(composition) is not PreparedContinuousComposition or (
            composition.source_evidence != source_evidence
            or composition.installed_commitments
            != tuple(c for d in transition.new_decisions for c in d.installed_commitments)
            or composition.resulting_heads.ledger_sha256 != cp.current.snapshot.journal_sha256
            or composition.resulting_heads.order_sha256 != cp.current.snapshot.order_sha256
        ):
            raise ContinuousAccountConflict("ACTUAL_COMPOSITION_HEADS_OR_COMMITMENTS_DIFFER")
        for reference in (composition.source_evidence, composition.decision_evidence):
            self._object(reference.object_ref)
        cp_ref, request_ref = self._put(cp), self._put(transition.request)
        canonical = CanonicalAccountTransitionRef(
            account_id=scope.account_id,
            account_binding_sha256=scope.account_binding_sha256,
            command_id=transition.command_id,
            command_sha256=transition.command_sha256,
            previous_checkpoint_sha256=transition.previous_checkpoint_sha256,
            checkpoint=cp_ref,
            checkpoint_sha256=cp.semantic_sha256,
            expected_heads=composition.expected_heads,
            resulting_heads=composition.resulting_heads,
            source_closure_sha256=transition.source_closure_sha256,
            applied_at=cp.now,
        )
        commit = ContinuousAccountCommit(
            scope,
            1 if previous is None else previous.receipt.commit.sequence + 1,
            None if previous is None else previous.receipt.commit.semantic_sha256,
            canonical,
            ContinuousEvidenceRef(
                CONTINUOUS_RUNTIME_ACTION_SCHEMA
                if type(transition.request) is ContinuousRuntimeAction
                else CONTINUOUS_REQUEST_SCHEMA,
                request_ref,
                transition.request.semantic_sha256,
            ),
            composition.source_evidence,
            composition.decision_evidence,
        )
        key = continuous_account_journal_key(scope)
        encoded = self.codec.encode_record(commit)
        if not 0 < len(encoded) <= MAX_CONTINUOUS_COMMIT_BYTES:
            raise ContinuousAccountConflict("CONTINUOUS_COMPACT_COMMIT_BOUND")
        journal = self.journal.prepare_append(
            key,
            JournalAppend(
                transition.command_id,
                transition.command_sha256,
                empty_head(key) if previous is None else previous.receipt.journal.committed_head,
                (JournalRecord(commit.semantic_sha256, CONTINUOUS_COMMIT_SCHEMA, encoded),),
            ),
        )
        record = ContinuousAccountRecord(commit, journal.receipt)
        payload = self.codec.encode_record(record)
        if not 0 < len(payload) <= MAX_CONTINUOUS_COMMIT_BYTES or (
            self.codec.decode_record(payload, ContinuousAccountRecord) != record
        ):
            raise ContinuousAccountConflict("CONTINUOUS_COMPACT_RECORD_BOUND_OR_CODEC")
        return self._own(
            PreparedContinuousCommit(
                commit,
                payload,
                journal,
                composition,
                previous,
                MappingProxyType(self._base_values(record, payload)),
                self._seal,
            )
        )

    def _capture_row(
        self,
        connection: Connection,
        scope: ContinuousAccountScope,
        command_id: str,
    ) -> ContinuousIndexSnapshot | None:
        self._connection(connection)
        row = (
            connection.execute(
                sa.select(*_columns(connection, commits)).where(
                    commits.c.account_id == scope.account_id,
                    commits.c.command_id == command_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else ContinuousIndexSnapshot(scope, MappingProxyType(dict(row)))

    def capture_commit_in_transaction(
        self,
        connection: Connection,
        *,
        scope: ContinuousAccountScope,
        command_id: str,
    ) -> ContinuousIndexSnapshot | None:
        return self._capture_row(connection, scope, command_id)

    def capture_current_in_transaction(
        self,
        connection: Connection,
        *,
        scope: ContinuousAccountScope,
    ) -> ContinuousIndexSnapshot | None:
        self._connection(connection)
        head = (
            connection.execute(
                sa.select(*_columns(connection, heads)).where(
                    heads.c.account_id == scope.account_id,
                )
            )
            .mappings()
            .one_or_none()
        )
        if head is None:
            retained = connection.execute(
                sa.select(
                    sa.exists().where(
                        commits.c.account_id == scope.account_id,
                    )
                )
            ).scalar_one()
            raw = self.journal.capture_in_transaction(
                connection, continuous_account_journal_key(scope)
            )
            if retained or raw.stream is not None or raw.empty_has_records:
                raise ContinuousAccountConflict("CONTINUOUS_EMPTY_HEAD_HAS_RETAINED_HISTORY")
            return None
        copied_head = dict(head)
        _validate_row(copied_head, heads)
        row = self._capture_row(connection, scope, copied_head["command_id"])
        if (
            row is None
            or self._head_values(row.row) != copied_head
            or (copied_head["scope_sha256"] != scope.semantic_sha256)
        ):
            raise ContinuousAccountConflict("CONTINUOUS_CURRENT_HEAD_DIFFERS")
        # A head may not silently hide later immutable account rows.
        if connection.execute(
            sa.select(
                sa.exists().where(
                    commits.c.account_id == scope.account_id,
                    commits.c.sequence > head["sequence"],
                )
            )
        ).scalar_one():
            raise ContinuousAccountConflict("CONTINUOUS_HEAD_HIDES_TAIL")
        return row

    def _decode_reference_row(
        self, snapshot: ContinuousIndexSnapshot
    ) -> tuple[ContinuousIndexSnapshot, ContinuousAccountReceipt]:
        row = snapshot.row
        _validate_row(row, commits)
        record = self.codec.decode_record(row["canonical_payload"], ContinuousAccountRecord)
        if type(record) is not ContinuousAccountRecord or (
            self.codec.encode_record(record) != row["canonical_payload"]
            or record.commit.scope != snapshot.scope
        ):
            raise ValueError("record")
        receipt = ContinuousAccountReceipt(
            record.commit,
            record.journal,
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
        values = self._base_values(record, row["canonical_payload"]) | self._receipt_values(receipt)
        if (
            values != row
            or record.journal.previous_head.key_sha256
            != (continuous_account_journal_key(snapshot.scope).semantic_sha256)
            or record.journal.record_hashes
            != (sha256(self.codec.encode_record(record.commit)).hexdigest(),)
        ):
            raise ValueError("mirrors")
        copied = ContinuousIndexSnapshot(snapshot.scope, MappingProxyType(values))
        return copied, receipt

    def capture_reference_in_transaction(
        self,
        connection: Connection,
        *,
        scope: ContinuousAccountScope,
        command_id: str,
        source_lease_sha256: str | None = None,
        journal_pool: DetachedJournalCapture | None = None,
    ) -> ContinuousReferenceSnapshot | None:
        """Copy one immutable publication and its immediate predecessor only.

        This does not capture a current execution state. Callers must charge
        these bounded copied rows to their aggregate source-read budget.
        """
        self._connection(connection)
        current = self._capture_row(connection, scope, command_id)
        if current is None:
            return None
        previous = None
        if current.row["sequence"] > 1:
            parent_command = connection.execute(
                sa.select(sa.func.substr(commits.c.command_id, 1, 129)).where(
                    commits.c.account_id == scope.account_id,
                    commits.c.sequence == current.row["sequence"] - 1,
                )
            ).scalar_one_or_none()
            if type(parent_command) is not str or not 0 < len(parent_command) <= 128:
                raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_PREDECESSOR_MISSING")
            previous = self._capture_row(connection, scope, parent_command)
            if previous is None:
                raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_PREDECESSOR_MISSING")
        key = continuous_account_journal_key(scope)

        def journal_capture(command: str) -> JournalReadSnapshot:
            captured = self.journal.capture_in_transaction(connection, key, command_id=command)
            return captured if journal_pool is None else journal_pool.capture(captured)

        raw = ContinuousReferenceSnapshot(
            current,
            _capture_lease(connection, current.row["lease_sha256"]),
            journal_capture(command_id),
            previous,
            None if previous is None else _capture_lease(connection, previous.row["lease_sha256"]),
            None if previous is None else journal_capture(previous.row["command_id"]),
            source_lease_sha256,
            None
            if source_lease_sha256 is None
            else _capture_lease(connection, source_lease_sha256),
        )
        self._reference_captures[id(raw)] = raw
        self._reference_capture_fields[id(raw)] = tuple(getattr(raw, f.name) for f in fields(raw))
        finalize(raw, self._reference_capture_fields.pop, id(raw), None)
        return raw

    def _require_reference_capture(self, raw: ContinuousReferenceSnapshot) -> None:
        if (
            type(raw) is not ContinuousReferenceSnapshot
            or self._reference_captures.get(id(raw)) is not raw
        ):
            raise ContinuousAccountConflict("OWNED_CONTINUOUS_REFERENCE_CAPTURE_REQUIRED")
        if any(
            getattr(raw, f.name) is not original
            for f, original in zip(
                fields(raw), self._reference_capture_fields[id(raw)], strict=True
            )
        ):
            raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_CAPTURE_CHANGED")

    def require_same_reference_capture(
        self,
        original: ContinuousReferenceSnapshot,
        fresh: ContinuousReferenceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare complete owner-issued metadata captures without resolving C."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousAccountConflict("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self._require_reference_capture(value)
        for left, right in ((original.current, fresh.current), (original.previous, fresh.previous)):
            if left is None or right is None:
                comparison.identity(left, right)
            else:
                if (
                    type(left) is not ContinuousIndexSnapshot
                    or type(right) is not ContinuousIndexSnapshot
                ):
                    raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_INDEX_TYPE_DIFFERS")
                comparison.data((left.scope, left.row), (right.scope, right.row))
        comparison.data(
            (
                original.lease,
                original.previous_lease,
                original.source_lease_sha256,
                original.source_lease,
            ),
            (fresh.lease, fresh.previous_lease, fresh.source_lease_sha256, fresh.source_lease),
        )
        self.journal.require_same_capture(original.journal, fresh.journal, comparison=comparison)
        if original.previous_journal is None or fresh.previous_journal is None:
            comparison.identity(original.previous_journal, fresh.previous_journal)
        else:
            self.journal.require_same_capture(
                original.previous_journal, fresh.previous_journal, comparison=comparison
            )
        for value in (original, fresh):
            self._require_reference_capture(value)

    def resolve_reference(
        self, snapshot: ContinuousReferenceSnapshot
    ) -> ResolvedContinuousReference:
        """Authenticate metadata/lease/journal without invoking the composer.

        The result binds immutable checkpoint object references. It does not
        decode those objects, replay economics or qualify an account to trade.
        """
        self._require_reference_capture(snapshot)
        try:
            _, receipt = self._decode_reference_row(snapshot.current)
            _validate_lease(snapshot.lease, receipt)
            journal = self.journal.resolve_snapshot(snapshot.journal)
            if journal.receipt != receipt.journal:
                raise ValueError("reference journal")
            prior = None
            prior_journal = None
            if snapshot.previous is None:
                if (
                    receipt.commit.sequence != 1
                    or snapshot.previous_lease is not None
                    or snapshot.previous_journal is not None
                ):
                    raise ValueError("reference genesis")
            else:
                if snapshot.previous_lease is None or snapshot.previous_journal is None:
                    raise ValueError("reference predecessor")
                _, prior = self._decode_reference_row(snapshot.previous)
                _validate_lease(snapshot.previous_lease, prior)
                prior_journal = self.journal.resolve_snapshot(snapshot.previous_journal)
                if (
                    prior_journal.receipt != prior.journal
                    or prior.commit.scope != receipt.commit.scope
                    or prior.commit.sequence + 1 != receipt.commit.sequence
                    or prior.commit.semantic_sha256 != receipt.commit.previous_commit_sha256
                    or prior.commit.transition.checkpoint_sha256
                    != receipt.commit.transition.previous_checkpoint_sha256
                    or prior.journal.committed_head != receipt.journal.previous_head
                ):
                    raise ValueError("reference original parent binding")
            source_lease = None
            if snapshot.source_lease_sha256 is not None:
                if snapshot.source_lease is None:
                    raise ValueError("reference source lease missing")
                source_lease = _decode_lease_row(snapshot.source_lease)
                if (
                    source_lease.semantic_sha256 != snapshot.source_lease_sha256
                    or source_lease.account_id != receipt.commit.scope.account_id
                ):
                    raise ValueError("reference source lease scope")
            elif snapshot.source_lease is not None:
                raise ValueError("reference extra lease")
            value = self._own(
                ResolvedContinuousReference(
                    snapshot, receipt, prior, journal, prior_journal, source_lease, self._seal
                )
            )
            self._reference_fingerprints[id(value)] = _reference_fingerprint(
                snapshot, journal, prior_journal
            )
            finalize(value, self._reference_fingerprints.pop, id(value), None)
            return value
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_REFERENCE_INVALID") from None

    def require_reference(self, value: ResolvedContinuousReference) -> None:
        """Check the original complete detached metadata graph outside SQL."""
        self._require(value, ResolvedContinuousReference)
        self._require_reference_capture(value.snapshot)
        if self._reference_fingerprints.get(id(value)) != _reference_fingerprint(
            value.snapshot, value.journal, value.previous_journal
        ):
            raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_CONTENT_CHANGED")

    def recheck_reference_in_transaction(
        self, connection: Connection, value: ResolvedContinuousReference
    ) -> None:
        """Recheck original compact rows and leases, allowing later publications."""
        self._connection(connection)
        self._require(value, ResolvedContinuousReference)
        self._require_reference_capture(value.snapshot)
        if (
            value.snapshot.source_lease_sha256 is not None
            and _capture_lease(connection, value.snapshot.source_lease_sha256)
            != value.snapshot.source_lease
        ):
            raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_SOURCE_LEASE_CHANGED")
        for index, lease, journal in (
            (value.snapshot.current, value.snapshot.lease, value.journal),
            (value.snapshot.previous, value.snapshot.previous_lease, value.previous_journal),
        ):
            if index is None:
                continue
            if (
                lease is None
                or journal is None
                or self._capture_row(connection, index.scope, index.row["command_id"]) != index
                or _capture_lease(connection, index.row["lease_sha256"]) != lease
            ):
                raise ContinuousAccountConflict("CONTINUOUS_REFERENCE_ROWS_CHANGED")
            self.journal.recheck_in_transaction(connection, journal, require_current_head=False)

    def resolve_index(
        self,
        snapshot: ContinuousIndexSnapshot,
        *,
        previous: ResolvedContinuousAccount | None = None,
    ) -> ResolvedContinuousIndex:
        """Resolve compact discovery; source planning requires the actual prior prefix.

        A non-genesis discovery with no predecessor is metadata-only, usable as
        a fixed-through page anchor. It cannot authorize a composition capture.
        """
        if previous is not None:
            self.require_resolved(previous)
        try:
            copied, receipt = self._decode_reference_row(snapshot)
            record = receipt.commit
            if previous is not None and (
                previous.receipt.commit.scope != record.scope
                or previous.receipt.commit.sequence + 1 != record.sequence
                or previous.receipt.commit.semantic_sha256 != record.previous_commit_sha256
                or previous.checkpoint.semantic_sha256
                != record.transition.previous_checkpoint_sha256
            ):
                raise ContinuousAccountConflict("CONTINUOUS_CAPTURE_PREFIX_DIFFERS")
            plan = None
            if record.sequence == 1 or previous is not None:
                plan = self.composer.prepare_capture(record, previous=previous)
                if (
                    type(plan) is not ContinuousCompositionPlan
                    or plan.commit_sha256 != record.semantic_sha256
                ):
                    raise ContinuousAccountConflict("CONTINUOUS_CAPTURE_PLAN_DIFFERS")
            return self._own(ResolvedContinuousIndex(copied, receipt, plan, self._seal))
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_INDEX_INVALID") from None

    def capture_snapshot_in_transaction(
        self,
        connection: Connection,
        *,
        index: ResolvedContinuousIndex,
    ) -> ContinuousAccountSnapshot:
        self._connection(connection)
        self._require(index, ResolvedContinuousIndex)
        if index.composition_plan is None:
            raise ContinuousAccountConflict("CONTINUOUS_CAPTURE_REQUIRES_PREVIOUS_PREFIX_PLAN")
        commit = index.receipt.commit
        current = self._capture_row(connection, commit.scope, commit.transition.command_id)
        if current != index.snapshot:
            raise ContinuousAccountConflict("CONTINUOUS_DISCOVERY_CHANGED")
        raw = self.journal.capture_in_transaction(
            connection,
            continuous_account_journal_key(commit.scope),
            command_id=commit.transition.command_id,
        )
        composition = self.composer.capture_in_transaction(
            connection,
            commit=commit,
            plan=index.composition_plan,
        )
        if type(composition) is not ContinuousCompositionSnapshot or (
            composition.commit_sha256 != index.snapshot.row["commit_sha256"]
        ):
            raise ContinuousAccountConflict("CONTINUOUS_COMPOSITION_CAPTURE_DIFFERS")
        lease = _capture_lease(connection, index.receipt.fence_reference.lease_sha256)
        return ContinuousAccountSnapshot(commit.scope, current.row, raw, composition, lease)

    def resolve_snapshot(
        self,
        snapshot: ContinuousAccountSnapshot,
        *,
        previous: ResolvedContinuousAccount | None,
    ) -> ResolvedContinuousAccount:
        """Authenticate each complete fixed-through prefix without rerunning the engine."""
        if previous is not None:
            self._require(previous, ResolvedContinuousAccount)
        index = self.resolve_index(
            ContinuousIndexSnapshot(snapshot.scope, snapshot.row), previous=previous
        )
        receipt, commit = index.receipt, index.receipt.commit
        _validate_lease(snapshot.lease, receipt)
        if (
            commit.sequence != (1 if previous is None else previous.receipt.commit.sequence + 1)
            or commit.previous_commit_sha256
            != (None if previous is None else previous.receipt.commit.semantic_sha256)
            or commit.transition.previous_checkpoint_sha256
            != (None if previous is None else previous.checkpoint.semantic_sha256)
            or (previous is not None and previous.receipt.commit.scope != commit.scope)
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RESTORE_PREFIX_DIFFERS")
        journal = self.journal.resolve_snapshot(snapshot.journal)
        if journal.receipt != receipt.journal or receipt.journal.previous_head != (
            empty_head(continuous_account_journal_key(commit.scope))
            if previous is None
            else previous.receipt.journal.committed_head
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_JOURNAL_DIFFERS")
        cp_bytes = self._object(commit.transition.checkpoint)
        cp = self.codec.decode_record(cp_bytes, CausalEngineCheckpoint)
        request_type: type[ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction]
        if commit.sequence == 1:
            request_type = ContinuousEngineInputs
        elif commit.request.schema_id == CONTINUOUS_RUNTIME_ACTION_SCHEMA:
            request_type = ContinuousRuntimeAction
        else:
            request_type = ClosedEngineFrontier
        request_bytes = self._object(commit.request.object_ref)
        request = self.codec.decode_record(request_bytes, request_type)
        if (
            type(cp) is not CausalEngineCheckpoint
            or type(request) is not request_type
            or (
                self.codec.encode_record(cp) != cp_bytes
                or self.codec.encode_record(request) != request_bytes
                or type(cp.inputs) is not ContinuousEngineInputs
                or cp.semantic_sha256 != commit.transition.checkpoint_sha256
                or request.semantic_sha256 != commit.request.semantic_sha256
                or cp.inputs.spec.account_id != commit.scope.account_id
                or cp.inputs.spec.deployment_id != commit.scope.stream_id
                or cp.inputs.spec.account_binding_sha256 != commit.scope.account_binding_sha256
                or cp.current.snapshot.journal_sha256
                != commit.transition.resulting_heads.ledger_sha256
                or cp.current.snapshot.order_sha256
                != commit.transition.resulting_heads.order_sha256
                or cp.now != commit.transition.applied_at
            )
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_ENGINE_BINDING_DIFFERS")
        if isinstance(request, ContinuousEngineInputs):
            expected_command = content_digest(
                ("continuous-initialize/1", request, commit.transition.source_closure_sha256)
            )
        elif isinstance(request, ContinuousRuntimeAction):
            expected_command = content_digest(("continuous-runtime-action/1", request))
        else:
            expected_command = content_digest(("continuous-frontier/1", request))
        if commit.transition.command_sha256 != expected_command:
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_COMMAND_DIFFERS")
        if isinstance(request, ContinuousEngineInputs):
            if request != cp.inputs or cp.runtime_decisions:
                raise ContinuousAccountConflict("CONTINUOUS_RETAINED_INITIALIZATION_DIFFERS")
        elif isinstance(request, ContinuousRuntimeAction):
            if (
                previous is None
                or cp.inputs != previous.checkpoint.inputs
                or request.previous_checkpoint_sha256 != previous.checkpoint.semantic_sha256
                or request.source_closure_sha256 != commit.transition.source_closure_sha256
                or request.checked_at != cp.now
                or cp.now < previous.checkpoint.now
                or cp.frontier != previous.checkpoint.frontier
                or cp.sequence != previous.checkpoint.sequence + int(request.command is not None)
                or (request.retained_id, request.semantic_sha256) not in cp.closed_source_frontiers
                or cp.runtime_decisions != previous.checkpoint.runtime_decisions
            ):
                raise ContinuousAccountConflict("CONTINUOUS_RETAINED_RUNTIME_ACTION_DIFFERS")
        elif (
            previous is None
            or cp.inputs != previous.checkpoint.inputs
            or request.previous_checkpoint_sha256 != previous.checkpoint.semantic_sha256
            or request.source_frontier_sha256 != commit.transition.source_closure_sha256
            or request.knowledge_at != cp.now
            or (request.frontier_id, request.semantic_sha256) not in cp.closed_source_frontiers
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_FRONTIER_DIFFERS")
        for ref in (commit.source_evidence, commit.decision_evidence):
            self._object(ref.object_ref)
        composition = self.composer.resolve(
            snapshot.composition,
            commit=commit,
            checkpoint=cp,
            request=request,
            previous=previous,
        )
        self.composer.require_resolved(composition)
        if type(composition) is not ResolvedContinuousComposition or (
            composition.commit_sha256 != commit.semantic_sha256
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_COMPOSITION_DIFFERS")
        result = self._own(
            ResolvedContinuousAccount(
                snapshot,
                receipt,
                cp,
                request,
                journal,
                composition,
                self._seal,
            )
        )
        if (
            previous is not None
            and commit.source_evidence.schema_id != VENUE_CAPTURE_CLOSURE_SCHEMA
        ):
            ancestor = (
                previous
                if previous.receipt.commit.source_evidence.schema_id == VENUE_CAPTURE_CLOSURE_SCHEMA
                else self._venue_ancestors.get(id(previous))
            )
            if ancestor is not None:
                self._venue_ancestors[id(result)] = ancestor
                finalize(result, self._venue_ancestors.pop, id(result), None)
        if (
            previous is not None
            and commit.source_evidence.schema_id != CONTINUOUS_QUOTE_CLOSURE_SCHEMA
        ):
            quote = (
                previous
                if previous.receipt.commit.source_evidence.schema_id
                == CONTINUOUS_QUOTE_CLOSURE_SCHEMA
                else self._quote_ancestors.get(id(previous))
            )
            if quote is not None:
                self._quote_ancestors[id(result)] = quote
                finalize(result, self._quote_ancestors.pop, id(result), None)
        return result

    def nearest_source_ancestor(
        self,
        previous: ResolvedContinuousAccount,
        *,
        schema_id: str,
    ) -> ResolvedContinuousAccount | None:
        """Return an owned venue or quote prefix linked during original account restore.

        The caller must still authenticate that prefix's applied reconciliation,
        original freshness and exact current seven heads. No SQL, recursive
        restore or mutable latest-result lookup is performed here.
        """
        self.require_resolved(previous)
        if schema_id not in (VENUE_CAPTURE_CLOSURE_SCHEMA, CONTINUOUS_QUOTE_CLOSURE_SCHEMA):
            raise ContinuousAccountConflict("CONTINUOUS_ANCESTOR_SCHEMA_UNSUPPORTED")
        if previous.receipt.commit.source_evidence.schema_id == schema_id:
            return previous
        ancestors = (
            self._venue_ancestors
            if schema_id == VENUE_CAPTURE_CLOSURE_SCHEMA
            else self._quote_ancestors
        )
        ancestor = ancestors.get(id(previous))
        if ancestor is not None:
            self.require_resolved(ancestor)
            if (
                ancestor.receipt.commit.scope != previous.receipt.commit.scope
                or ancestor.receipt.commit.sequence >= previous.receipt.commit.sequence
                or ancestor.receipt.commit.source_evidence.schema_id != schema_id
            ):
                raise ContinuousAccountConflict("CONTINUOUS_ANCESTOR_LINEAGE_DIFFERS")
        return ancestor

    def capture_page_in_transaction(
        self,
        connection: Connection,
        *,
        through: ResolvedContinuousIndex,
        after: ResolvedContinuousAccount | None = None,
        limit: int = MAX_CONTINUOUS_PAGE,
    ) -> tuple[ContinuousIndexSnapshot, ...]:
        self._connection(connection)
        self._require(through, ResolvedContinuousIndex)
        if after is not None:
            self._require(after, ResolvedContinuousAccount)
        if type(limit) is not int or not 1 <= limit <= MAX_CONTINUOUS_PAGE:
            raise ContinuousAccountConflict("CONTINUOUS_PAGE_BOUND")
        scope, end = through.receipt.commit.scope, through.receipt.commit.sequence
        start = 0 if after is None else after.receipt.commit.sequence
        if start > end or (after is not None and after.receipt.commit.scope != scope):
            raise ContinuousAccountConflict("CONTINUOUS_PAGE_SCOPE_OR_PREFIX")
        if (
            self._capture_row(connection, scope, through.receipt.commit.transition.command_id)
            != through.snapshot
        ):
            raise ContinuousAccountConflict("CONTINUOUS_PAGE_ANCHOR_CHANGED")
        if after is not None and self._capture_row(
            connection, scope, after.receipt.commit.transition.command_id
        ) != (ContinuousIndexSnapshot(scope, after.snapshot.row)):
            raise ContinuousAccountConflict("CONTINUOUS_PAGE_PREDECESSOR_CHANGED")
        rows = tuple(
            ContinuousIndexSnapshot(scope, MappingProxyType(dict(row)))
            for row in connection.execute(
                sa.select(*_columns(connection, commits))
                .where(
                    commits.c.account_id == scope.account_id,
                    commits.c.sequence > start,
                    commits.c.sequence <= end,
                )
                .order_by(commits.c.sequence)
                .limit(limit)
            ).mappings()
        )
        if tuple(row.row["sequence"] for row in rows) != tuple(
            range(start + 1, min(end, start + limit) + 1)
        ):
            raise ContinuousAccountConflict("CONTINUOUS_PAGE_INCOMPLETE")
        return rows

    def restore(
        self,
        scope: ContinuousAccountScope,
        *,
        command_id: str | None = None,
    ) -> ResolvedContinuousAccount | None:
        """Restore original objects through one immutable command, in bounded pages."""
        with _repeatable_read_transaction(self.engine) as connection:
            raw = (
                self.capture_current_in_transaction(connection, scope=scope)
                if command_id is None
                else self.capture_commit_in_transaction(
                    connection,
                    scope=scope,
                    command_id=command_id,
                )
            )
        if raw is None:
            return None
        through = self.resolve_index(raw)
        previous = None
        while (
            previous is None or previous.receipt.commit.sequence < through.receipt.commit.sequence
        ):
            with _repeatable_read_transaction(self.engine) as connection:
                rows = self.capture_page_in_transaction(connection, through=through, after=previous)
            for row in rows:
                index = self.resolve_index(row, previous=previous)
                with _repeatable_read_transaction(self.engine) as connection:
                    snapshot = self.capture_snapshot_in_transaction(connection, index=index)
                previous = self.resolve_snapshot(snapshot, previous=previous)
        return previous

    def require_resolved(self, value: ResolvedContinuousAccount) -> None:
        """Require this store's original resolved identity and metadata fingerprint.

        Call outside SQL. This performs no fresh read, restore, codec or replay.
        """
        self._require(value, ResolvedContinuousAccount)
        if (
            value.checkpoint.semantic_sha256 != value.receipt.commit.transition.checkpoint_sha256
            or value.request.semantic_sha256 != value.receipt.commit.request.semantic_sha256
        ):
            raise ContinuousAccountConflict("OWNED_RESTORED_ENGINE_CONTENT_CHANGED")

    def recheck_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedContinuousAccount,
        *,
        require_current: bool,
    ) -> None:
        self._connection(connection)
        self._require(resolved, ResolvedContinuousAccount)
        commit = resolved.receipt.commit
        expected = ContinuousIndexSnapshot(commit.scope, resolved.snapshot.row)
        if self._capture_row(connection, commit.scope, commit.transition.command_id) != expected:
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_INDEX_CHANGED")
        if (
            _capture_lease(connection, resolved.receipt.fence_reference.lease_sha256)
            != resolved.snapshot.lease
        ):
            raise ContinuousAccountConflict("CONTINUOUS_RETAINED_LEASE_CHANGED")
        if (
            require_current
            and self.capture_current_in_transaction(connection, scope=commit.scope) != expected
        ):
            raise ContinuousAccountConflict("CONTINUOUS_CURRENT_PREFIX_CHANGED")
        self.journal.recheck_in_transaction(
            connection,
            resolved.journal,
            require_current_head=require_current,
        )
        self.composer.recheck_in_transaction(
            connection, resolved.composition, require_current=require_current
        )

    def retry_in_transaction(
        self,
        connection: Connection,
        *,
        original: ResolvedContinuousAccount,
        command_sha256: str,
        fence: AccountFence,
    ) -> ContinuousAccountReceipt:
        """Inert historical retry. Call restore(command_id=...) before any engine work."""
        self._mutation_connection(connection)
        self._require(original, ResolvedContinuousAccount)
        if original.receipt.commit.transition.command_sha256 != command_sha256 or (
            fence.account_id != original.receipt.commit.scope.account_id
        ):
            raise ContinuousAccountConflict("CONTINUOUS_IMMUTABLE_RETRY_CONFLICT")
        lock_account_capacity_serialization(connection, fence.account_id)
        self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        self.recheck_in_transaction(connection, original, require_current=False)
        self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        return original.receipt

    def commit_in_transaction(
        self,
        connection: Connection,
        *,
        prepared: PreparedContinuousCommit,
        fence: AccountFence,
    ) -> ContinuousAccountReceipt:
        """Caller owns COMMIT. A failed operation rolls back all coupled writes."""
        self._mutation_connection(connection)
        self._require(prepared, PreparedContinuousCommit)
        commit = prepared.commit
        if type(fence) is not AccountFence or fence.account_id != commit.scope.account_id:
            raise ContinuousAccountConflict("CONTINUOUS_ACCOUNT_FENCE_SCOPE")
        lock_account_capacity_serialization(connection, fence.account_id)
        try:
            with connection.begin_nested():
                checked = self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
                if (
                    self._capture_row(connection, commit.scope, commit.transition.command_id)
                    is not None
                ):
                    # Publication after an ambiguous acknowledgment must rediscover
                    # the retained original; no recomputation/refresh under lock.
                    raise ContinuousAccountConflict("CONTINUOUS_RESTORE_ORIGINAL_RETRY_REQUIRED")
                current = self.capture_current_in_transaction(connection, scope=commit.scope)
                prior = prepared.previous
                expected = (
                    None
                    if prior is None
                    else ContinuousIndexSnapshot(commit.scope, prior.snapshot.row)
                )
                if current != expected:
                    raise ContinuousAccountConflict("CONTINUOUS_CURRENT_PREFIX_CHANGED")
                if prior is not None:
                    self.recheck_in_transaction(connection, prior, require_current=True)
                resulting = self.composer.apply_in_transaction(
                    connection,
                    prepared.composition,
                    fence=fence,
                    fence_receipt=checked,
                )
                if resulting != commit.transition.resulting_heads or (
                    resulting.lease_generation != checked.fence.fencing_generation
                ):
                    raise ContinuousAccountConflict("CONTINUOUS_ACTUAL_RESULTING_HEADS_DIFFER")
                journal = self.journal.append_in_transaction(connection, prepared.journal)
                if journal != prepared.journal.receipt:
                    raise ContinuousAccountConflict("CONTINUOUS_ACTUAL_JOURNAL_DIFFERS")
                receipt = ContinuousAccountReceipt(
                    commit,
                    journal,
                    checked.validated_at,
                    ContinuousFenceReference(
                        checked.fence.owner_id,
                        checked.fence.lease_id,
                        checked.fence.fencing_generation,
                        checked.lease_sha256,
                        checked.policy_sha256,
                        checked.valid_until,
                    ),
                )
                values = dict(prepared.row_values) | self._receipt_values(receipt)
                insertion = sqlite_insert if connection.dialect.name == "sqlite" else pg_insert
                inserted = connection.execute(
                    insertion(commits)
                    .values(**values)
                    .on_conflict_do_nothing()
                    .returning(
                        commits.c.commit_sha256,
                    )
                ).scalar_one_or_none()
                if inserted != prepared.row_values["commit_sha256"]:
                    raise ContinuousAccountConflict("CONTINUOUS_INDEX_INSERT_CONFLICT")
                new_head = self._head_values(values)
                if prior is None:
                    changed = connection.execute(
                        insertion(heads)
                        .values(**new_head)
                        .on_conflict_do_nothing()
                        .returning(
                            heads.c.commit_sha256,
                        )
                    ).scalar_one_or_none()
                else:
                    changed = connection.execute(
                        sa.update(heads)
                        .where(
                            heads.c.account_id == fence.account_id,
                            heads.c.commit_sha256 == prior.snapshot.row["commit_sha256"],
                            heads.c.sequence == prior.snapshot.row["sequence"],
                        )
                        .values(**new_head)
                        .returning(heads.c.commit_sha256)
                    ).scalar_one_or_none()
                if changed != prepared.row_values["commit_sha256"]:
                    raise ContinuousAccountConflict("CONTINUOUS_HEAD_CAS_CONFLICT")
                stored = self.capture_current_in_transaction(connection, scope=commit.scope)
                if stored is None or stored.row != values:
                    raise ContinuousAccountConflict("CONTINUOUS_INDEX_READBACK_DIFFERS")
                final_receipt = self.coordinator.revalidate_for_commit_in_transaction(
                    connection, fence
                )
                self._require(prepared, PreparedContinuousCommit)
                if prepared.composition.valid_until is not None and (
                    final_receipt.validated_at >= prepared.composition.valid_until
                ):
                    raise ContinuousAccountConflict("CONTINUOUS_PUBLICATION_DEADLINE_EXPIRED")
                publication = _PendingContinuousPublication(
                    prepared,
                    receipt,
                    fence,
                    fence.semantic_sha256,
                    stored,
                    self.journal.capture_in_transaction(
                        connection, prepared.journal.key, command_id=journal.command_id
                    ),
                    _capture_lease(connection, receipt.fence_reference.lease_sha256),
                )
            # Register only after the nested transaction has successfully exited.
            # The outer owner cannot publish after this original fence/deadline.
            self._pending_publications[id(connection)].append(publication)
            return receipt
        except IntegrityError:
            raise ContinuousAccountConflict("CONTINUOUS_SQL_CONFLICT") from None
