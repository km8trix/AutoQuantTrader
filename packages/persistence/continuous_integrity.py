"""Detached integrity validation through actual configured simulation stores.

The input SQL snapshot is data, never owned receipt authority. This reader binds
it to fresh coherent rows, authenticates every original journal/account prefix,
and checks the same rows again after detached validation. It returns no risk,
readiness, dispatch or trading capability and never renews original source times.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from operator import le
from threading import RLock, Thread, current_thread
from types import MappingProxyType, TracebackType
from typing import TYPE_CHECKING, Any, Literal, cast
from weakref import WeakKeyDictionary

from sqlalchemy import Column, Connection, Engine, Integer, String, Table
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, Case, quoted_name
from sqlalchemy.sql.operators import in_op

from packages.domain.account_coordinator import AccountFence
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousAccountScope,
)
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.durable_journal_contracts import JournalKey, empty_head
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence.account_coordinator import (
    CommittedAccountObservations,
    SqlAccountCoordinator,
)
from packages.persistence.applied_reconciliation_schema import (
    APPLIED_RECONCILIATION_TABLES,
    applied_reconciliation_commits,
)
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.continuous_account_schema import (
    CONTINUOUS_ACCOUNT_TABLES,
    continuous_account_commits,
)
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import (
    MAX_ROWS,
    DailyRuntimeRawSnapshot,
    ResolvedDailyRuntimeSnapshot,
    SqlDailyRuntimeRisk,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_admissions,
    daily_runtime_hold_events,
)
from packages.persistence.database import (
    CONTINUOUS_INTEGRITY_DEPENDENCY_TABLES,
    EXPECTED_SCHEMA_REVISION,
    ContinuousIntegritySnapshot,
    _capture_continuous_integrity_snapshot,
    _repeatable_read_transaction,
    verify_operational_schema,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.schema import phase2_account_lease_heads

if TYPE_CHECKING:
    from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations

TABLES = (
    *JOURNAL_TABLES,
    *APPLIED_RECONCILIATION_TABLES,
    *DAILY_RUNTIME_TABLES,
    *CONTINUOUS_ACCOUNT_TABLES,
)


class ContinuousIntegrityError(ValueError):
    """Configured original simulation history is incomplete, changed, or unauthenticated."""


class _OriginalObjects:
    """Keep the existing 32 MiB detached object bound across this whole validation."""

    def __init__(self, account: SqlContinuousAccount) -> None:
        self.account = account
        self.references: dict[str, ObjectRef] = {}
        self.total = 0

    def inspect(self, value: object) -> None:
        pending, seen = [value], set()
        while pending:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if type(item) is ObjectRef:
                original = self.references.get(item.object_sha256)
                if original is not None:
                    if original != item:
                        raise ContinuousIntegrityError("ORIGINAL_OBJECT_IDENTITY_DIFFERS")
                    continue
                self.total += item.byte_count
                if self.total > MAX_CONTINUOUS_OBJECT_BYTES or len(self.references) >= MAX_ROWS:
                    raise ContinuousIntegrityError("CONTINUOUS_ORIGINAL_OBJECT_CLOSURE_BOUND")
                payload = self.account.artifacts.read(item, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
                if (
                    len(payload) != item.byte_count
                    or sha256(payload).hexdigest() != item.object_sha256
                ):
                    raise ContinuousIntegrityError("ORIGINAL_OBJECT_BYTES_DIFFER")
                self.references[item.object_sha256] = item
            elif is_dataclass(item) and not isinstance(item, type):
                pending.extend(getattr(item, field.name) for field in fields(item))
            elif type(item) is tuple:
                pending.extend(item)
            elif isinstance(item, Mapping):
                pending.extend(item.values())

    def recheck(self) -> None:
        for reference in self.references.values():
            payload = self.account.artifacts.read(reference, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
            if (
                len(payload) != reference.byte_count
                or sha256(payload).hexdigest() != reference.object_sha256
            ):
                raise ContinuousIntegrityError("ORIGINAL_OBJECT_CHANGED_DURING_VALIDATION")


@dataclass(frozen=True, slots=True)
class _OriginalDailyEpisode:
    reader: SqlContinuousIntegrityReader
    composer: SqlContinuousCommitComposer
    current: ResolvedDailyRuntimeSnapshot
    original: ContinuousIntegritySnapshot
    observations: CommittedAccountObservations
    objects: _OriginalObjects
    thread: Thread
    maximum_borrows: int


@dataclass(slots=True)
class _DailyEpisodeState:
    episode: _OriginalDailyEpisode
    originals: tuple[object, ...]
    borrows: int = 0
    failed: bool = False


@dataclass(frozen=True, slots=True)
class _FactoryResult:
    actual: ResolvedContinuousAccount
    current: ResolvedDailyRuntimeSnapshot
    original: ContinuousIntegritySnapshot
    observations: CommittedAccountObservations
    objects: _OriginalObjects
    object_mapping: dict[str, ObjectRef]
    object_total: int
    object_fields: tuple[tuple[str, ObjectRef, str, int, str], ...]
    snapshot_fields: tuple[object, ...]
    structure: tuple[_FactoryBinding, ...]


@dataclass(slots=True)
class _FactoryReadState:
    reader: SqlContinuousIntegrityReader
    coordinator: SqlAccountCoordinator
    thread: Thread
    stack: ExitStack
    originals: tuple[object, ...] = ()
    entered: int = 0
    completed: bool = False
    failed: bool = False
    faults: int = 0
    result: _FactoryResult | None = None
    result_fields: tuple[object, ...] = ()
    scope: _OriginalFactoryRead | None = None
    final_started: bool = False
    final_completed: bool = False
    final_read: _FactoryFinalDaily | None = None
    final_fields: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class _FactoryFinalDaily:
    raw: DailyRuntimeRawSnapshot
    structure: tuple[_FactoryBinding, ...]


@dataclass(slots=True)
class _FactoryScopeState:
    reader: SqlContinuousIntegrityReader
    thread: Thread
    phase: str = "created"
    failed: bool = False
    manager: Any = None
    operation: _FactoryReadState | None = None
    originals: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class _FactoryScopeOwner:
    reader: SqlContinuousIntegrityReader
    thread: Thread
    state: _FactoryScopeState
    manager: Any = None
    closed: bool = False


class _OriginalFactoryRead:
    """Owned one-use wrapper; reject misuse before delegating to a generator."""

    __slots__ = ("__weakref__",)

    def __enter__(self) -> ResolvedContinuousAccount:
        with _FACTORY_READ_LOCK:
            owner = _FACTORY_SCOPES.get(self)
            if owner is None:
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_REQUIRED")
            scope = owner.state
            if (
                owner.closed
                or owner.manager is not None
                or owner.thread is not current_thread()
                or scope.failed
                or scope.phase != "created"
                or scope.reader is not owner.reader
                or scope.thread is not owner.thread
            ):
                _fail_factory_scope(self, owner)
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_ENTRY_REQUIRED")
            scope.phase = "entering"
            manager = owner.reader._factory_operation(scope=self)
            scope.manager = manager
            scope.originals = (owner.reader, owner.thread, manager)
            owner = replace(owner, manager=manager)
            _FACTORY_SCOPES[self] = owner
        try:
            result = manager.__enter__()
            with _FACTORY_READ_LOCK:
                if scope.failed or scope.phase != "entering" or not _factory_scope_fields(owner):
                    raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_ENTRY_CHANGED")
                scope.phase = "active"
            return result.actual
        except BaseException:
            # Damaged operation metadata must not stop original-manager cleanup.
            # The original entry failure already prevents a successful handoff.
            with suppress(BaseException):
                _fail_factory_scope(self, owner)
            # A yielded generator still needs original-owner cleanup if wrapper
            # entry subsequently fails. Never drive it from a foreign thread.
            with suppress(BaseException):
                manager.gen.close()
            with _FACTORY_READ_LOCK:
                scope.phase = "closed"
                scope.operation = None
                _FACTORY_SCOPES[self] = replace(owner, closed=True)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        with _FACTORY_READ_LOCK:
            owner = _FACTORY_SCOPES.get(self)
            if owner is None:
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_REQUIRED")
            if owner.thread is not current_thread():
                _fail_factory_scope(self, owner)
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_EXIT_THREAD")
            if owner.closed or owner.manager is None:
                _fail_factory_scope(self, owner)
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_EXIT_REQUIRED")
            scope = owner.state
            preflight: BaseException | None = None
            try:
                if scope.phase != "active" or not _factory_scope_fields(owner) or scope.failed:
                    raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_CHANGED")
            except BaseException as error:
                preflight = error
                # Preserve the first failure and still drive the captured
                # manager when fault marking also encounters deleted metadata.
                with suppress(BaseException):
                    _fail_factory_scope(self, owner)
            manager = owner.manager
            scope.phase = "closing"
        # The immutable original manager remains usable if a mutable slot was
        # deleted. A body BaseException wins over preflight and cleanup failures.
        primary = exc if exc is not None else preflight
        failure = preflight
        try:
            try:
                manager.__exit__(
                    exc_type if exc is not None else None if primary is None else type(primary),
                    primary,
                    traceback,
                )
            except BaseException as error:
                if failure is None:
                    failure = error
            try:
                with _FACTORY_READ_LOCK:
                    if (
                        _FACTORY_SCOPES.get(self) is not owner
                        or scope.failed
                        or scope.phase != "closing"
                        or not _factory_scope_fields(owner)
                    ):
                        raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_CLOSING_CHANGED")
            except BaseException as error:
                if failure is None:
                    failure = error
                with suppress(BaseException):
                    _fail_factory_scope(self, owner)
        finally:
            with _FACTORY_READ_LOCK:
                scope.phase = "closed"
                scope.operation = None
                _FACTORY_SCOPES[self] = replace(owner, closed=True)
        if exc is not None:
            return False
        if failure is not None:
            raise failure
        return False


_FACTORY_SCOPES: WeakKeyDictionary[_OriginalFactoryRead, _FactoryScopeOwner] = WeakKeyDictionary()


def _factory_scope_fields(owner: _FactoryScopeOwner) -> bool:
    scope = owner.state
    return (
        type(scope.originals) is tuple
        and len(scope.originals) == 3
        and all(
            value is original
            for value, original in zip(
                (scope.reader, scope.thread, scope.manager),
                (owner.reader, owner.thread, owner.manager),
                strict=True,
            )
        )
        and all(
            value is original
            for value, original in zip(
                scope.originals, (owner.reader, owner.thread, owner.manager), strict=True
            )
        )
    )


def _fail_factory_scope(wrapper: _OriginalFactoryRead, owner: _FactoryScopeOwner) -> None:
    with _FACTORY_READ_LOCK:
        owner.state.failed = True
        operation = _ACTIVE_FACTORY_READS.get(owner.reader)
        if operation is not None and (
            operation.scope is wrapper
            or (
                type(operation.originals) is tuple
                and len(operation.originals) == 5
                and operation.originals[4] is wrapper
            )
        ):
            _fail_factory(operation)


# This is an active-operation ownership registry, never a resolved-result cache.
# It is populated only for the fixed synchronous call and removed on every exit.
_ACTIVE_FACTORY_READS: dict[SqlContinuousIntegrityReader, _FactoryReadState] = {}
_FACTORY_READ_LOCK = RLock()


# Additional, deliberately narrower handoff limits. Count edges before allocating
# their snapshots; artifact byte limits do not imply a Python object-count limit.
def _fail_factory(state: _FactoryReadState) -> None:
    with _FACTORY_READ_LOCK:
        state.failed = True
        state.faults += 1


# Version 2 explicitly permits an original capture plus a separately bounded
# fresh capture. Version 1's single 16,384-record joint limit rejected retained
# history; this is a new resource profile, not qualification of that old limit.
_FACTORY_HANDOFF_PROFILE = "original-and-fresh-structure/2"
_MAX_FACTORY_CONTAINERS = 16_384
_MAX_FACTORY_FRESH_CONTAINERS = 16_384
_MAX_FACTORY_COMBINED_CONTAINERS = 32_768
_MAX_FACTORY_BINDINGS = 131_072
_FactoryBinding = tuple[str, object, type[object], tuple[str, ...], tuple[object, ...]]
_FACTORY_SCALARS = (type(None), bool, int, str, bytes, date, datetime, Decimal)
_FACTORY_TABLES = (*TABLES, *CONTINUOUS_INTEGRITY_DEPENDENCY_TABLES)


def _factory_structure(
    roots: tuple[object, ...],
    *,
    account: SqlContinuousAccount | None = None,
    daily: SqlDailyRuntimeRisk | None = None,
    original: tuple[_FactoryBinding, ...] = (),
) -> tuple[_FactoryBinding, ...]:
    """Seal original handoff data; known owners remain subject to full graph guards."""
    if (account is None) != (daily is None) or (
        account is not None
        and (type(account) is not SqlContinuousAccount or type(daily) is not SqlDailyRuntimeRisk)
    ):
        raise ContinuousIntegrityError("FACTORY_HANDOFF_EXACT_CONFIGURATION_REQUIRED")
    if len(roots) > _MAX_FACTORY_BINDINGS:
        raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")
    # Preserve the original records, including their original field identities;
    # never reseal mutated original data while extending to a fresh capture.
    # The initial result has exactly three roots. Its recorded values account
    # for every other charged edge, including declared SQL configuration.
    original_count = len(original)
    # Reject an oversized original inventory before iterating or copying it.
    if original_count > _MAX_FACTORY_CONTAINERS:
        raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")
    container_limit = (
        min(original_count + _MAX_FACTORY_FRESH_CONTAINERS, _MAX_FACTORY_COMBINED_CONTAINERS)
        if original
        else _MAX_FACTORY_CONTAINERS
    )
    edges = len(roots) + (3 if original else 0) + sum(len(record[4]) for record in original)
    if edges > _MAX_FACTORY_BINDINGS or original_count > container_limit:
        raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")
    pending = list(roots)
    seen: set[int] = {id(record[1]) for record in original}
    records: list[_FactoryBinding] = list(original)

    def charge(count: int) -> None:
        nonlocal edges
        edges += count
        if edges > _MAX_FACTORY_BINDINGS or len(records) >= container_limit:
            raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")

    def attributes(value: object, names: tuple[str, ...], *, descend: bool = True) -> None:
        charge(len(names))
        values = tuple(getattr(value, name) for name in names)
        records.append(("fields", value, type(value), names, values))
        if descend:
            pending.extend(values)

    while pending:
        item = pending.pop()
        if type(item) in _FACTORY_SCALARS or type(item) is object:
            continue
        if id(item) in seen:
            continue
        seen.add(id(item))
        if (item is account and type(item) is SqlContinuousAccount) or (
            item is daily and type(item) is SqlDailyRuntimeRisk
        ):
            # RuntimeOperatingPlan retains these exact configured owners. Their
            # original identity/type is pinned here; full owner/source guards,
            # not traversal of arbitrary store internals, remain authoritative.
            attributes(item, (), descend=False)
        elif type(item) is quoted_name:
            if item.quote is not None and item.quote is not True and item.quote is not False:
                raise ContinuousIntegrityError("FACTORY_HANDOFF_SQL_NAME_QUOTE_INVALID")
            # The str content is immutable. Its one SQL quoting flag is not.
            attributes(item, ("quote",), descend=False)
        elif type(item) in (tuple, list):
            sequence = cast(tuple[object, ...] | list[object], item)
            charge(len(sequence))
            values = tuple(sequence)
            records.append(("sequence", item, type(item), (), values))
            pending.extend(values)
        elif type(item) in (dict, MappingProxyType):
            mapping = cast(Mapping[object, object], item)
            charge(2 * len(mapping))
            values = tuple(part for pair in mapping.items() for part in pair)
            records.append(("mapping", item, type(item), (), values))
            pending.extend(values)
        elif isinstance(item, Enum):
            attributes(item, ("_name_", "_value_"))
        elif is_dataclass(item) and not isinstance(item, type):
            # Preflight class field inventory before materializing its bindings.
            if edges + len(type(item).__dataclass_fields__) > _MAX_FACTORY_BINDINGS:
                raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")
            attributes(item, tuple(field.name for field in fields(item)))
        elif type(item) is Table:
            if not any(item is table for table in _FACTORY_TABLES):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_SQL_TABLE")
            # Original declared configuration only, never MetaData internals.
            attributes(item, ("schema", "name", "metadata", "columns"), descend=False)
            pending.extend((item.schema, item.name))
            charge(len(item.columns))
            columns = tuple(item.columns)
            records.append(("sequence", item.columns, type(item.columns), (), columns))
            pending.extend(columns)
        elif type(item) is Column:
            if not any(item is column for table in _FACTORY_TABLES for column in table.columns):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_SQL_COLUMN")
            attributes(
                item,
                ("table", "name", "key", "type", "nullable", "primary_key"),
                descend=False,
            )
            pending.extend((item.table, item.name, item.key))
            # These are the original column type's scalar SQL characteristics.
            names = tuple(
                name
                for name in ("length", "precision", "scale", "timezone", "asdecimal")
                if hasattr(item.type, name)
            )
            attributes(item.type, names, descend=False)
        elif type(item) is BinaryExpression:
            if (
                type(item.left) is not Column
                or item.operator not in (le, in_op)
                or (
                    type(item.right) is Case
                    and (
                        item.left is not daily_runtime_hold_events.c.revision
                        or item.operator is not le
                    )
                )
            ):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_SQL_PREDICATE")
            attributes(
                item,
                ("left", "right", "operator", "negate", "type", "modifiers"),
                descend=False,
            )
            pending.extend((item.left, item.right, item.modifiers))
        elif type(item) is Case:
            # Only the original B hold-revision lookup, never arbitrary SQL CASE.
            if (
                item.value is not daily_runtime_hold_events.c.hold_id
                or type(item.whens) is not list
                or type(item.type) is not Integer
            ):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_SQL_CASE")
            # Preflight before scanning/copying pairs. Each original mapping pair
            # occupies an ordered tuple record as well as a list edge; the
            # unchanged aggregate traversal still charges every actual binding.
            if (
                edges + 4 + len(item.whens) > _MAX_FACTORY_BINDINGS
                or len(records) + 2 + len(item.whens) > container_limit
            ):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_STRUCTURE_BOUND")

            def literal(value: object, *, key: bool = False) -> bool:
                if type(value) is not BindParameter:
                    return False
                return (
                    value.callable is None
                    and value.expanding is False
                    and value.expand_op is None
                    and value.literal_execute is False
                    and (
                        type(value.value) is str
                        and type(value.type) is String
                        and value.type.length is None
                        and value.type.collation is None
                        if key
                        else type(value.value) is int and type(value.type) is Integer
                    )
                )

            default = cast(BindParameter[Any], item.else_)
            if (
                not literal(default)
                or default.value != 0
                or any(
                    type(pair) is not tuple
                    or len(pair) != 2
                    or not literal(pair[0], key=True)
                    or not literal(pair[1])
                    or pair[1].value < 0
                    for pair in item.whens
                )
            ):
                raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_SQL_CASE")
            attributes(item, ("value", "whens", "else_", "type"), descend=False)
            pending.extend((item.value, item.whens, item.else_))
            # Literal types are narrowly known configuration, not a generic
            # TypeEngine graph. Pin class and the String flags used by this form.
            literal_types = (item.type, default.type)
            for sql_type in literal_types:
                if id(sql_type) not in seen:
                    seen.add(id(sql_type))
                    attributes(sql_type, (), descend=False)
            for key, revision in item.whens:
                for sql_type in (key.type, revision.type):
                    if id(sql_type) not in seen:
                        seen.add(id(sql_type))
                        names = ("length", "collation") if type(sql_type) is String else ()
                        attributes(sql_type, names, descend=False)
        elif type(item) is BindParameter:
            if item.callable is not None:
                raise ContinuousIntegrityError("FACTORY_HANDOFF_DYNAMIC_SQL_BIND")
            attributes(
                item,
                ("key", "value", "callable", "type", "expanding", "expand_op", "literal_execute"),
                descend=False,
            )
            pending.append(item.value)
        else:
            raise ContinuousIntegrityError("FACTORY_HANDOFF_UNKNOWN_MUTABLE_VALUE")
    return tuple(records)


def _require_factory_structure(records: tuple[_FactoryBinding, ...]) -> None:
    """Bounded identity comparisons only: no hashing, serialization or external I/O."""
    for kind, original, original_type, names, values in records:
        # Kind is issued only by the exact bounded constructor above.
        item: Any = original
        if type(item) is not original_type:
            raise ContinuousIntegrityError("FACTORY_HANDOFF_ORIGINAL_TYPE_CHANGED")
        if kind == "fields":
            changed = any(
                getattr(item, name) is not value for name, value in zip(names, values, strict=True)
            )
        elif kind == "sequence":
            sequence = cast(Any, item)
            if original_type is tuple and sequence is values:
                # An exact tuple cannot change its own member identities. Every
                # mutable descendant still has its separate binding below.
                changed = False
            else:
                changed = len(sequence) != len(values) or any(
                    a is not b for a, b in zip(sequence, values, strict=True)
                )
        else:
            mapping = cast(Mapping[object, object], item)
            changed = 2 * len(mapping) != len(values) or any(
                key is not values[2 * index] or value is not values[2 * index + 1]
                for index, (key, value) in enumerate(mapping.items())
            )
        if changed:
            raise ContinuousIntegrityError("FACTORY_HANDOFF_ORIGINAL_STRUCTURE_CHANGED")


class SqlContinuousIntegrityReader:
    """One configured financial account with a legitimately held current owner fence."""

    def __init__(
        self,
        engine: Engine,
        *,
        scope: ContinuousAccountScope,
        reconciliation_scope: ReconciliationScope,
        account: SqlContinuousAccount,
        daily: SqlDailyRuntimeRisk,
        publisher: SqlContinuousReconciliationPublication,
        associations: SqlRuntimeOwnerAssociations,
        journals: tuple[SqlDurableJournal, ...],
        fence: AccountFence,
    ) -> None:
        from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations

        composer = account.composer
        if (
            type(scope) is not ContinuousAccountScope
            or type(reconciliation_scope) is not ReconciliationScope
            or type(account) is not SqlContinuousAccount
            or type(daily) is not SqlDailyRuntimeRisk
            or type(publisher) is not SqlContinuousReconciliationPublication
            or type(associations) is not SqlRuntimeOwnerAssociations
            or type(composer) is not SqlContinuousCommitComposer
            or type(daily.producers) is not SqlContinuousRuntimeSources
            or type(fence) is not AccountFence
            or type(journals) is not tuple
            or not journals
            or any(type(journal) is not SqlDurableJournal for journal in journals)
            or any(
                journal._engine is not engine or journal._codec is not account.codec
                for journal in journals
            )
            or any(
                store.engine is not engine
                for store in (account, daily, publisher, associations, composer)
            )
            or publisher.account is not account
            or publisher.composer is not composer
            or composer.daily is not daily
            or composer.producer_history is not daily.producers
            or composer.fence != fence
            or daily.coordinator is not account.coordinator
            or publisher.coordinator is not account.coordinator
            or associations.accounts is not account
            or associations.daily is not daily
            or associations.publisher is not publisher
            or scope.account_id != fence.account_id
            or scope.account_id != account.coordinator.account_id
            or reconciliation_scope.account_id != scope.account_id
            or reconciliation_scope.binding_sha256 != scope.account_binding_sha256
        ):
            raise ContinuousIntegrityError("EXACT_CONFIGURED_INTEGRITY_STORES_REQUIRED")
        self.engine, self.scope, self.reconciliation_scope = engine, scope, reconciliation_scope
        self.account, self.daily, self.publisher = account, daily, publisher
        self.associations, self.journals, self.fence, self.composer = (
            associations,
            journals,
            fence,
            composer,
        )
        self._original_graph = self._graph()
        self._instance = self
        self._daily_episode: _DailyEpisodeState | None = None
        self._factory_read: _FactoryReadState | None = None

    def _require_factory_read(self, state: _FactoryReadState) -> None:
        if (
            type(state) is not _FactoryReadState
            or _ACTIVE_FACTORY_READS.get(self) is not state
            or self._factory_read is not state
            or len(state.originals) != 5
            or any(
                value is not original
                for value, original in zip(
                    (state.reader, state.coordinator, state.thread, state.stack, state.scope),
                    state.originals,
                    strict=True,
                )
            )
            or state.reader is not self
            or state.coordinator is not self.account.coordinator
            or state.thread is not current_thread()
            or state.failed
        ):
            raise ContinuousIntegrityError("ORIGINAL_FACTORY_READ_OPERATION_REQUIRED")
        self._require_graph()

    def _select_factory_read(self) -> _FactoryReadState | None:
        # Select the hidden original operation before graph checks or any fallback.
        with _FACTORY_READ_LOCK:
            state = _ACTIVE_FACTORY_READS.get(self)
            if state is not None:
                try:
                    self._require_factory_read(state)
                except BaseException:
                    _fail_factory(state)
                    raise
            elif self._factory_read is not None:
                raise ContinuousIntegrityError("UNREGISTERED_FACTORY_READ_OPERATION")
            return state

    def _require_factory_result(self, state: _FactoryReadState) -> _FactoryResult:
        self._require_factory_read(state)
        result = state.result
        if (
            state.entered != 1
            or not state.completed
            or type(result) is not _FactoryResult
            or len(state.result_fields) != 1 + len(fields(_FactoryResult))
            or state.result_fields[0] is not result
            or any(
                getattr(result, field.name) is not value
                for field, value in zip(fields(result), state.result_fields[1:], strict=True)
            )
            or self._daily_episode is not None
            or self.composer._integrity_daily is not None
            or self.composer._integrity_daily_active is not None
        ):
            raise ContinuousIntegrityError("COMPLETE_ORIGINAL_FACTORY_RESULT_REQUIRED")
        state.coordinator._require_observations(result.observations)
        return result

    def _require_factory_objects(self, result: _FactoryResult) -> None:
        objects = result.objects
        if (
            objects.account is not self.account
            or objects.references is not result.object_mapping
            or objects.total != result.object_total
            or len(objects.references) != len(result.object_fields)
            or any(
                value is not original
                for value, original in zip(
                    (
                        result.original.revision,
                        result.original.tables,
                        result.original.dependencies,
                    ),
                    result.snapshot_fields,
                    strict=True,
                )
            )
        ):
            raise ContinuousIntegrityError("ORIGINAL_FACTORY_OBJECT_INVENTORY_CHANGED")
        for key, reference, digest, count, version in result.object_fields:
            if objects.references.get(key) is not reference or (
                reference.object_sha256,
                reference.byte_count,
                reference.codec_version,
            ) != (digest, count, version):
                raise ContinuousIntegrityError("ORIGINAL_FACTORY_OBJECT_REFERENCE_CHANGED")

    def original_factory_read(self) -> _OriginalFactoryRead:
        """Create the fixed provisional factory scope; this grants no authority."""
        wrapper = _OriginalFactoryRead()
        with _FACTORY_READ_LOCK:
            thread = current_thread()
            _FACTORY_SCOPES[wrapper] = _FactoryScopeOwner(
                self, thread, _FactoryScopeState(self, thread)
            )
        return wrapper

    def _provisional_factory_state(self) -> _FactoryReadState:
        state = self._select_factory_read()
        if state is None:
            raise ContinuousIntegrityError("ACTIVE_ORIGINAL_FACTORY_SCOPE_REQUIRED")
        try:
            owner = None if state.scope is None else _FACTORY_SCOPES.get(state.scope)
            scope = None if owner is None else owner.state
            if (
                owner is None
                or scope is None
                or owner.closed
                or owner.reader is not self
                or owner.thread is not current_thread()
                or not _factory_scope_fields(owner)
                or scope.reader is not self
                or scope.thread is not current_thread()
                or scope.operation is not state
                or scope.failed
                or scope.phase != "active"
                or len(scope.originals) != 3
                or any(
                    value is not original
                    for value, original in zip(
                        (scope.reader, scope.thread, scope.manager), scope.originals, strict=True
                    )
                )
            ):
                raise ContinuousIntegrityError("ORIGINAL_PROVISIONAL_FACTORY_SCOPE_REQUIRED")
            return state
        except BaseException:
            _fail_factory(state)
            raise

    def _factory_final_structure(
        self, state: _FactoryReadState, result: _FactoryResult
    ) -> tuple[_FactoryBinding, ...]:
        final = state.final_read
        if final is None:
            if (
                state.final_fields
                or state.final_started is not False
                or state.final_completed is not False
            ):
                raise ContinuousIntegrityError("ORIGINAL_FINAL_DAILY_CAPTURE_REQUIRED")
            return result.structure
        if (
            type(final) is not _FactoryFinalDaily
            or state.final_started is not True
            or state.final_completed is not True
            or len(state.final_fields) != 3
            or any(
                value is not original
                for value, original in zip(
                    (final, final.raw, final.structure), state.final_fields, strict=True
                )
            )
        ):
            raise ContinuousIntegrityError("ORIGINAL_FINAL_DAILY_CAPTURE_CHANGED")
        self.daily._require_owned(final.raw)
        return final.structure

    def require_original_factory_values(self) -> None:
        """Check provisional original fields only; no codec, hash, artifact or SQL."""
        state = self._provisional_factory_state()
        try:
            result = self._require_factory_result(state)
            self._require_factory_objects(result)
            _require_factory_structure(self._factory_final_structure(state, result))
        except BaseException:
            _fail_factory(state)
            raise

    def read_original_daily_for_factory(self) -> ResolvedDailyRuntimeSnapshot:
        """Freshly capture complete B, then reuse only the exact equal original B."""
        state = self._provisional_factory_state()
        try:
            result = self._require_factory_result(state)
            if (
                state.final_started is not False
                or state.final_completed is not False
                or state.final_read is not None
            ):
                raise ContinuousIntegrityError("FINAL_FACTORY_DAILY_READ_ALREADY_USED")
            state.final_started = True
            raw = self.daily.read_snapshot(account_id=self.scope.account_id, fence=self.fence)
            self._require_factory_result(state)
            self._require_factory_objects(result)
            _require_factory_structure(result.structure)
            # Keep original records and charge fresh descendants into their SAME
            # container/edge allowance. No resealing or second independent cap.
            combined = _factory_structure(
                (raw,), account=self.account, daily=self.daily, original=result.structure
            )
            final = _FactoryFinalDaily(raw, combined)
            state.final_read = final
            state.final_fields = (final, raw, combined)
            self.daily.require_same_complete_capture(result.current, raw)
            self._require_factory_result(state)
            state.final_completed = True
            self._factory_final_structure(state, result)
            return result.current
        except BaseException:
            _fail_factory(state)
            raise

    def _verify_factory_terminal(self, state: _FactoryReadState, result: _FactoryResult) -> None:
        """The existing full post-schema block, once at the final output boundary."""
        if state.scope is not None and state.final_completed is not True:
            raise ContinuousIntegrityError("COMPLETE_FINAL_FACTORY_DAILY_READ_REQUIRED")
        structure = self._factory_final_structure(state, result)
        self.account.require_resolved(result.actual)
        self.composer.require_resolved(result.actual.composition)
        self._require_daily_graph(result.current)
        self._require_factory_objects(result)
        _require_factory_structure(structure)
        result.objects.recheck()
        self._require_factory_objects(result)
        self._require_factory_result(state)
        _require_factory_structure(structure)
        with _repeatable_read_transaction(self.engine) as connection:
            # Compare committed rows before B's rollback-only clock observation.
            self._recheck_original_rows(connection, result.original, result.observations)
            self.account.recheck_in_transaction(connection, result.actual, require_current=True)
            self.daily.recheck_snapshot_in_transaction(connection, result.current, fence=self.fence)
            state.coordinator.revalidate_for_commit_in_transaction(connection, self.fence)
        self._require_factory_result(state)
        self._require_factory_objects(result)
        if self._factory_final_structure(state, result) is not structure:
            raise ContinuousIntegrityError("ORIGINAL_FACTORY_TERMINAL_STRUCTURE_CHANGED")
        _require_factory_structure(structure)

    def verify_original_for_factory(self) -> ResolvedContinuousAccount:
        """Return the same original C only after fixed full-schema verification closes.

        Later state is denied, not adopted. This is an explicit factory contract
        change; the standalone schema and account restore APIs remain unchanged.
        """
        with self._factory_operation() as result:
            return result.actual

    @contextmanager
    def _factory_operation(
        self, *, scope: _OriginalFactoryRead | None = None
    ) -> Iterator[_FactoryResult]:
        with _FACTORY_READ_LOCK:
            active = _ACTIVE_FACTORY_READS.get(self)
            if active is not None:
                _fail_factory(active)
                raise ContinuousIntegrityError("FACTORY_READ_OPERATION_ALREADY_ACTIVE")
            if self._factory_read is not None or self._daily_episode is not None:
                raise ContinuousIntegrityError("FACTORY_READ_OPERATION_ALREADY_ACTIVE")
            stack = ExitStack()
            coordinator = self.account.coordinator
            state = _FactoryReadState(self, coordinator, current_thread(), stack)
            state.scope = scope
            if scope is not None:
                owner = _FACTORY_SCOPES.get(scope)
                if (
                    owner is None
                    or owner.reader is not self
                    or owner.thread is not current_thread()
                    or owner.state.phase != "entering"
                    or owner.state.failed
                    or owner.state.operation is not None
                    or owner.closed
                    or not _factory_scope_fields(owner)
                ):
                    raise ContinuousIntegrityError("ORIGINAL_FACTORY_SCOPE_OPERATION_REQUIRED")
                owner.state.operation = state
            owner_fields = (self, coordinator, state.thread, stack, scope)
            state.originals = owner_fields
            _ACTIVE_FACTORY_READS[self] = state
            self._factory_read = state
        primary = False
        result: _FactoryResult | None = None
        original_fields: tuple[object, ...] = ()
        original_final_fields: tuple[object, ...] = ()
        try:
            self._require_factory_read(state)
            verify_operational_schema(
                self.engine,
                require_phase_zero_facts=False,
                research_codec=self.account.codec,
                continuous_integrity=self,
            )
            result = self._require_factory_result(state)
            original_fields = state.result_fields
            if scope is None:
                original_final_fields = (
                    state.final_started,
                    state.final_completed,
                    state.final_read,
                    state.final_fields,
                )
                self._verify_factory_terminal(state, result)
            else:
                self._require_factory_objects(result)
            yield result
            if scope is not None:
                self._require_factory_result(state)
                original_final_fields = (
                    state.final_started,
                    state.final_completed,
                    state.final_read,
                    state.final_fields,
                )
                self._verify_factory_terminal(state, result)
        except BaseException:
            primary = True
            raise
        finally:
            # Metadata can itself be damaged. Capture failures without allowing
            # them to skip original stack cleanup or original-state retirement.
            cleanup_error: BaseException | None = None
            was_failed = True
            original_faults = None
            final_owner_fields: tuple[object, ...] = ()
            final_structure: tuple[_FactoryBinding, ...] = ()
            try:
                with _FACTORY_READ_LOCK:
                    was_failed = getattr(state, "failed", True)
                    original_faults = getattr(state, "faults", None)
                    state.failed = True
                    state.result = None
                    state.result_fields = ()
                current_final_fields = (
                    state.final_started,
                    state.final_completed,
                    state.final_read,
                    state.final_fields,
                )
                final_owner_fields = original_final_fields or current_final_fields
                if any(
                    value is not original
                    for value, original in zip(
                        current_final_fields, final_owner_fields, strict=True
                    )
                ):
                    raise ContinuousIntegrityError("ORIGINAL_FACTORY_FINAL_CAPTURE_CHANGED")
                final_structure = result.structure if result is not None else ()
                original_final = final_owner_fields[2]
                if type(original_final) is _FactoryFinalDaily:
                    final_structure = original_final.structure
                if result is not None and state.final_completed:
                    final_structure = self._factory_final_structure(state, result)
            except BaseException as error:
                cleanup_error = error
            try:
                stack.close()
                if (
                    was_failed
                    or state.faults != original_faults
                    or state.failed is not True
                    or state.result is not None
                    or state.result_fields != ()
                    or any(
                        value is not original
                        for value, original in zip(
                            (
                                state.final_started,
                                state.final_completed,
                                state.final_read,
                                state.final_fields,
                            ),
                            final_owner_fields,
                            strict=True,
                        )
                    )
                    or state.originals is not owner_fields
                    or any(
                        value is not original
                        for value, original in zip(
                            (
                                state.reader,
                                state.coordinator,
                                state.thread,
                                state.stack,
                                state.scope,
                            ),
                            owner_fields,
                            strict=True,
                        )
                    )
                    or _ACTIVE_FACTORY_READS.get(self) is not state
                    or self._factory_read is not state
                    or coordinator._state.observations is not None
                ):
                    raise ContinuousIntegrityError("ORIGINAL_FACTORY_READ_OPERATION_CHANGED")
                self._require_graph()
                if result is not None:
                    if original_fields[0] is not result or any(
                        getattr(result, field.name) is not value
                        for field, value in zip(fields(result), original_fields[1:], strict=True)
                    ):
                        raise ContinuousIntegrityError("ORIGINAL_FACTORY_RESULT_CHANGED_ON_CLOSE")
                    self._require_factory_objects(result)
                    if self._factory_final_structure(state, result) is not final_structure:
                        raise ContinuousIntegrityError("ORIGINAL_FACTORY_FINAL_CAPTURE_CHANGED")
                    _require_factory_structure(final_structure)
                    if self._factory_final_structure(state, result) is not final_structure:
                        raise ContinuousIntegrityError("ORIGINAL_FACTORY_FINAL_CAPTURE_CHANGED")
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            finally:
                # Selection, fault marking and this last retirement share one
                # short lock. Retirement is attempted even if metadata capture,
                # original close, or a post-close field check failed.
                retirement_error: BaseException | None = None
                unchanged = False
                with _FACTORY_READ_LOCK:
                    try:
                        unchanged = (
                            not was_failed
                            and state.faults == original_faults
                            and state.failed is True
                            and state.result is None
                            and state.result_fields == ()
                            and all(
                                value is original
                                for value, original in zip(
                                    (
                                        state.final_started,
                                        state.final_completed,
                                        state.final_read,
                                        state.final_fields,
                                    ),
                                    final_owner_fields,
                                    strict=True,
                                )
                            )
                            and state.originals is owner_fields
                            and (
                                state.final_read is None
                                or (
                                    type(state.final_read) is _FactoryFinalDaily
                                    and type(state.final_fields) is tuple
                                    and len(state.final_fields) == 3
                                    and state.final_read is state.final_fields[0]
                                    and state.final_read.raw is state.final_fields[1]
                                    and state.final_read.structure is state.final_fields[2]
                                    and state.final_read.structure is final_structure
                                )
                            )
                            and all(
                                value is original
                                for value, original in zip(
                                    (
                                        state.reader,
                                        state.coordinator,
                                        state.thread,
                                        state.stack,
                                        state.scope,
                                    ),
                                    owner_fields,
                                    strict=True,
                                )
                            )
                            and _ACTIVE_FACTORY_READS.get(self) is state
                            and self._factory_read is state
                            and coordinator._state.observations is None
                        )
                    except BaseException as error:
                        retirement_error = error
                    finally:
                        if _ACTIVE_FACTORY_READS.get(self) is state:
                            del _ACTIVE_FACTORY_READS[self]
                        if self._factory_read is state:
                            self._factory_read = None
                if cleanup_error is None:
                    if retirement_error is not None:
                        cleanup_error = retirement_error
                    elif not unchanged:
                        cleanup_error = ContinuousIntegrityError(
                            "FACTORY_READ_CHANGED_BEFORE_RETIREMENT"
                        )
            if cleanup_error is not None and not primary:
                raise cleanup_error

    def _graph(self) -> tuple[object, ...]:
        return (
            self.engine,
            self.scope,
            self.reconciliation_scope,
            self.account,
            self.daily,
            self.publisher,
            self.associations,
            self.journals,
            self.fence,
            self.composer,
            self.account.composer,
            self.composer.daily,
            self.composer.producer_history,
            self.daily.producers,
            self.account.coordinator,
            self.daily.coordinator,
            self.publisher.account,
            self.publisher.composer,
            self.publisher.coordinator,
            self.associations.accounts,
            self.associations.daily,
            self.associations.publisher,
            self.account.artifacts,
            self.account.codec,
            self.daily.codec,
            self.publisher.artifacts,
            self.publisher.codec,
            self.associations.commands,
            self.associations.artifacts,
            self.associations.codec,
            *(
                store.engine
                for store in (
                    self.account,
                    self.daily,
                    self.publisher,
                    self.associations,
                    self.composer,
                )
            ),
            *(journal for journal in self.journals),
            *(
                value
                for journal in self.journals
                for value in (journal._engine, journal._codec, journal._types)
            ),
        )

    def _require_graph(self) -> None:
        current = self._graph()
        if (
            self._instance is not self
            or len(current) != len(self._original_graph)
            or any(a is not b for a, b in zip(current, self._original_graph, strict=True))
            or self.composer.fence != self.fence
        ):
            raise ContinuousIntegrityError("ORIGINAL_INTEGRITY_CONFIGURATION_CHANGED")

    def _require_daily_graph(self, current: ResolvedDailyRuntimeSnapshot) -> None:
        self._require_graph()
        self.daily.require_resolved_snapshot(current)
        producer = self.daily.producers
        assert type(producer) is SqlContinuousRuntimeSources
        if current.attempt_sources is not None:
            producer._attempt_reader().require_resolved(current.attempt_sources)
        if current.observed_sources is not None:
            producer._observed_reader().require_resolved(current.observed_sources)
        self.daily.require_resolved_snapshot(current)
        self._require_graph()

    def _owned_daily_episode_for(
        self, episode: _OriginalDailyEpisode, *, consumer: SqlContinuousCommitComposer
    ) -> _DailyEpisodeState | None:
        """Select a private original owner; all validation remains in the borrow."""
        state = self._daily_episode
        if (
            self._instance is not self
            or type(episode) is not _OriginalDailyEpisode
            or type(state) is not _DailyEpisodeState
            or state.episode is not episode
            or type(state.originals) is not tuple
            or len(state.originals) != len(fields(_OriginalDailyEpisode))
            or state.originals[0] is not self
            or state.originals[1] is not consumer
        ):
            return None
        return state

    def _require_daily_episode_identity(self, episode: _OriginalDailyEpisode) -> _DailyEpisodeState:
        state = self._daily_episode
        if (
            type(episode) is not _OriginalDailyEpisode
            or state is None
            or state.failed
            or state.episode is not episode
            or episode.reader is not self
            or episode.composer is not self.composer
            or episode.thread is not current_thread()
            or episode.objects.account is not self.account
            or any(
                getattr(episode, field.name) is not value
                for field, value in zip(fields(episode), state.originals, strict=True)
            )
        ):
            raise ContinuousIntegrityError("ORIGINAL_DAILY_EPISODE_REQUIRED")
        self._require_graph()
        self.account.coordinator._require_observations(episode.observations)
        return state

    def _require_daily_episode(self, episode: _OriginalDailyEpisode) -> _DailyEpisodeState:
        state = self._require_daily_episode_identity(episode)
        self._require_daily_graph(episode.current)
        return state

    @contextmanager
    def _original_daily_episode(
        self,
        *,
        original: ContinuousIntegritySnapshot,
        observations: CommittedAccountObservations,
        current: ResolvedDailyRuntimeSnapshot,
        objects: _OriginalObjects,
    ) -> Iterator[_OriginalDailyEpisode]:
        self._require_daily_graph(current)
        raw = current.raw
        if (
            self._daily_episode is not None
            or raw.receipt.fence != self.fence
            or raw.command_id is not None
            or raw.input_refs is not None
            or raw.owner_command_ref is not None
            or raw.requested_envelopes
            or raw.requested_preparations
            or raw.requested_observed_source is not None
            or objects.account is not self.account
        ):
            raise ContinuousIntegrityError("ORIGINAL_COMPLETE_DAILY_VALIDATION_REQUIRED")
        objects.inspect(current)
        self._require_daily_graph(current)
        with _repeatable_read_transaction(self.engine) as connection:
            # Compare committed rows BEFORE B's rollback-only clock observation.
            self._recheck_original_rows(connection, original, observations)
            self.daily.recheck_snapshot_in_transaction(connection, current, fence=self.fence)
            self.account.coordinator.revalidate_for_commit_in_transaction(connection, self.fence)
        count = len(original.tables[continuous_account_commits.name])
        composer = self.composer
        episode = _OriginalDailyEpisode(
            self,
            composer,
            current,
            original,
            observations,
            objects,
            current_thread(),
            2 * count + int(count == 1),
        )
        state = _DailyEpisodeState(
            episode, tuple(getattr(episode, field.name) for field in fields(episode))
        )
        self._daily_episode = state
        primary_failure = False
        try:
            composer._bind_integrity_daily(self, episode)
            yield episode
            # The final SQL/fence check has already run. Only exact context and
            # binding identities are inspected during normal scope cleanup.
            self._require_daily_episode_identity(episode)
            composer._require_integrity_daily(self, episode)
        except BaseException:
            primary_failure = True
            raise
        finally:
            try:
                composer._unbind_integrity_daily(self, episode)
            except BaseException:
                if not primary_failure:
                    raise
            finally:
                # Even failed cleanup cannot strand our original binding or
                # replace a primary failure. Never clear another episode.
                binding = composer._integrity_daily
                if (
                    type(binding) is tuple
                    and len(binding) == 2
                    and binding[0] is self
                    and binding[1] is episode
                ):
                    composer._integrity_daily = None
                if composer._integrity_daily_active is episode:
                    composer._integrity_daily_active = None
                state.failed = True
                if self._daily_episode is state:
                    self._daily_episode = None

    def _borrow_original_daily(
        self, episode: _OriginalDailyEpisode, *, consumer: SqlContinuousCommitComposer
    ) -> ResolvedDailyRuntimeSnapshot:
        try:
            state = self._require_daily_episode(episode)
            if consumer is not self.composer or state.borrows >= episode.maximum_borrows:
                raise ContinuousIntegrityError("ORIGINAL_DAILY_EPISODE_CONSUMER_OR_BOUND")
            consumer._require_integrity_daily(self, episode)
            state.borrows += 1
            # Preserve the actual observation at each replaced read boundary.
            # Its new receipt must never replace the original B/source receipt.
            self.account.coordinator.revalidate(self.fence)
            episode.objects.recheck()
            self._require_daily_episode(episode)
            with _repeatable_read_transaction(self.engine) as connection:
                self.account.coordinator.recheck_committed_observations_in_transaction(
                    connection, episode.observations
                )
                self.daily.recheck_snapshot_in_transaction(
                    connection, episode.current, fence=self.fence
                )
                self.account.coordinator.revalidate_for_commit_in_transaction(
                    connection, self.fence
                )
            self._require_daily_episode(episode)
            consumer._require_integrity_daily(self, episode)
            return episode.current
        except BaseException:
            if self._daily_episode is not None:
                self._daily_episode.failed = True
            raise

    def _capture(self) -> ContinuousIntegritySnapshot | None:
        with _repeatable_read_transaction(self.engine) as connection:
            snapshot = _capture_continuous_integrity_snapshot(connection, tables=TABLES)
            # This trusted-clock guard rolls back with the read transaction; its
            # temporary observation must not replace the original captured row.
            self.account.coordinator.revalidate_for_commit_in_transaction(connection, self.fence)
            return snapshot

    def _recheck_final(
        self,
        original: ContinuousIntegritySnapshot,
        observations: CommittedAccountObservations,
    ) -> None:
        with _repeatable_read_transaction(self.engine) as connection:
            self._recheck_original_rows(connection, original, observations)
            # All SQL rows are checked before the final actual clock sample.
            # Only this rollback-only transaction sees that temporary update.
            self.account.coordinator.revalidate_for_commit_in_transaction(connection, self.fence)

    def _recheck_original_rows(
        self,
        connection: Connection,
        original: ContinuousIntegritySnapshot,
        observations: CommittedAccountObservations,
    ) -> None:
        actual = _capture_continuous_integrity_snapshot(connection, tables=TABLES)
        final_head = self.account.coordinator.recheck_committed_observations_in_transaction(
            connection, observations
        )
        dependencies = dict(original.dependencies)
        dependencies[phase2_account_lease_heads.name] = tuple(
            final_head if row["account_id"] == self.scope.account_id else row
            for row in dependencies[phase2_account_lease_heads.name]
        )
        expected = replace(original, dependencies=MappingProxyType(dependencies))
        if actual != expected:
            raise ContinuousIntegrityError("CONTINUOUS_ORIGINAL_ROWS_CHANGED_DURING_VALIDATION")

    def validate_snapshot(self, snapshot: ContinuousIntegritySnapshot) -> None:
        state = None
        try:
            state = self._select_factory_read()
            if state is not None:
                self._require_factory_read(state)
                if state.entered != 0:
                    raise ContinuousIntegrityError("FACTORY_SCHEMA_VALIDATION_MUST_BE_ONCE")
                state.entered += 1
            self._validate(snapshot)
        except ContinuousIntegrityError:
            if state is not None:
                _fail_factory(state)
            raise
        except Exception:
            if state is not None:
                _fail_factory(state)
            raise ContinuousIntegrityError("CONTINUOUS_RETAINED_INTEGRITY_FAILED") from None
        except BaseException:
            if state is not None:
                _fail_factory(state)
            raise

    def _validate(self, snapshot: ContinuousIntegritySnapshot) -> None:
        state = self._select_factory_read()
        self._require_graph()
        if (
            type(snapshot) is not ContinuousIntegritySnapshot
            or snapshot.revision != EXPECTED_SCHEMA_REVISION
        ):
            raise ContinuousIntegrityError("EXACT_CONTINUOUS_SQL_SNAPSHOT_REQUIRED")
        original = self._capture()
        if original is None or original != snapshot:
            raise ContinuousIntegrityError("CONTINUOUS_SQL_SNAPSHOT_CHANGED")
        heads = tuple(
            row
            for row in original.dependencies[phase2_account_lease_heads.name]
            if row["account_id"] == self.scope.account_id
        )
        if len(heads) != 1:
            raise ContinuousIntegrityError("ORIGINAL_ACCOUNT_OBSERVATION_HEAD_REQUIRED")
        if state is None:
            with self.account.coordinator.inspect_committed_observations(
                self.fence, original_head=heads[0]
            ) as observations:
                self._validate_original(original, observations)
            return
        self._require_factory_read(state)
        observations = state.stack.enter_context(
            state.coordinator.inspect_committed_observations(self.fence, original_head=heads[0])
        )
        result = self._validate_original(original, observations)
        self._require_factory_read(state)
        if result is None or result is not state.result:
            raise ContinuousIntegrityError("NONEMPTY_ORIGINAL_FACTORY_ACCOUNT_REQUIRED")
        state.completed = True
        self._require_factory_result(state)
        self._require_factory_objects(result)

    def _validate_original(
        self,
        original: ContinuousIntegritySnapshot,
        observations: CommittedAccountObservations,
    ) -> _FactoryResult | None:
        # Only the coherent rows captured by this configured engine drive validation.
        self._check_scope(original)
        objects = _OriginalObjects(self.account)
        self._validate_journals(original, objects)
        current = self.daily.resolve_snapshot(
            self.daily.read_snapshot(
                account_id=self.scope.account_id,
                fence=self.fence,
            )
        )
        with self._original_daily_episode(
            original=original, observations=observations, current=current, objects=objects
        ) as episode:
            actual = self._validate_accounts(original, current, objects)
            for generation in range(1, len(current.assignment_rows) + 1):
                association = self.associations.read(
                    self.scope,
                    current=current,
                    assignment_generation=generation,
                )
                self.associations.require_association(association)
                objects.inspect(association)
                with _repeatable_read_transaction(self.engine) as connection:
                    self.associations.recheck_in_transaction(connection, association)
            result = None
            state = self._select_factory_read()
            if state is not None and actual is not None:
                self._require_factory_read(state)
                result = _FactoryResult(
                    actual,
                    current,
                    original,
                    observations,
                    objects,
                    objects.references,
                    objects.total,
                    tuple(
                        (
                            key,
                            reference,
                            reference.object_sha256,
                            reference.byte_count,
                            reference.codec_version,
                        )
                        for key, reference in sorted(objects.references.items())
                    ),
                    # This is this reader's actual private capture, whose mapping
                    # proxies/tuple inventories/scalar row copies are immutable.
                    (original.revision, original.tables, original.dependencies),
                    _factory_structure(
                        (actual, current, objects.references),
                        account=self.account,
                        daily=self.daily,
                    ),
                )
                state.result = result
                state.result_fields = (
                    result,
                    *(getattr(result, field.name) for field in fields(result)),
                )
            self._require_graph()
            objects.recheck()
            self._require_daily_episode(episode)
            episode.composer._require_integrity_daily(self, episode)
            self._recheck_final(original, observations)
        return result

    def _check_scope(self, snapshot: ContinuousIntegritySnapshot) -> None:
        for table in (*DAILY_RUNTIME_TABLES, *CONTINUOUS_ACCOUNT_TABLES):
            if any(
                row["account_id"] != self.scope.account_id for row in snapshot.tables[table.name]
            ):
                raise ContinuousIntegrityError("UNCONFIGURED_FINANCIAL_ACCOUNT_HISTORY")
        if any(
            row["scope_sha256"] != self.reconciliation_scope.semantic_sha256
            for row in snapshot.tables[applied_reconciliation_commits.name]
        ):
            raise ContinuousIntegrityError("UNCONFIGURED_RECONCILIATION_SCOPE_HISTORY")

    def _validate_journals(
        self, snapshot: ContinuousIntegritySnapshot, objects: _OriginalObjects
    ) -> None:
        appends: dict[str, list[Mapping[str, Any]]] = {}
        schemas: dict[str, set[str]] = {}
        entry_rows: dict[str, list[Mapping[str, Any]]] = {}
        for row in snapshot.tables[journal_appends.name]:
            appends.setdefault(row["key_sha256"], []).append(row)
        for row in snapshot.tables[journal_entries.name]:
            schemas.setdefault(row["key_sha256"], set()).add(row["schema_id"])
            entry_rows.setdefault(row["key_sha256"], []).append(row)
        for row in snapshot.tables[journal_streams.name]:
            key = self.account.codec.decode_record(row["key_payload"], JournalKey)
            if (
                type(key) is not JournalKey
                or self.account.codec.encode_record(key) != row["key_payload"]
                or key.semantic_sha256 != row["key_sha256"]
            ):
                raise ContinuousIntegrityError("ORIGINAL_JOURNAL_KEY_DIFFERS")
            allowed = schemas.get(key.semantic_sha256, set())
            journal = next(
                (candidate for candidate in self.journals if allowed <= candidate._types.keys()),
                None,
            )
            if journal is None:
                raise ContinuousIntegrityError("CONFIGURED_TYPED_JOURNAL_READER_MISSING")
            for entry in entry_rows.get(key.semantic_sha256, ()):
                value = self.account.codec.decode_record(
                    entry["payload"], journal._types[entry["schema_id"]]
                )
                objects.inspect(value)
            with _repeatable_read_transaction(self.engine) as connection:
                raw = journal.capture_in_transaction(connection, key)
            head = journal.resolve_snapshot(raw).head
            previous = empty_head(key)
            for append in sorted(
                appends.get(key.semantic_sha256, ()), key=lambda value: value["previous_sequence"]
            ):
                with _repeatable_read_transaction(self.engine) as connection:
                    captured = journal.capture_in_transaction(
                        connection, key, command_id=append["command_id"]
                    )
                resolved = journal.resolve_snapshot(captured)
                receipt = resolved.receipt
                if receipt is None or receipt.previous_head != previous or resolved.head != head:
                    raise ContinuousIntegrityError("COMPLETE_JOURNAL_APPEND_CHAIN_DIFFERS")
                previous = receipt.committed_head
                with _repeatable_read_transaction(self.engine) as connection:
                    journal.recheck_in_transaction(connection, resolved, require_current_head=True)
            if previous != head:
                raise ContinuousIntegrityError("COMPLETE_JOURNAL_INVENTORY_DIFFERS")

    def _validate_accounts(
        self,
        snapshot: ContinuousIntegritySnapshot,
        current: ResolvedDailyRuntimeSnapshot,
        objects: _OriginalObjects,
    ) -> ResolvedContinuousAccount | None:
        with _repeatable_read_transaction(self.engine) as connection:
            raw = self.account.capture_current_in_transaction(connection, scope=self.scope)
        expected = snapshot.tables[continuous_account_commits.name]
        if raw is None:
            if (
                expected
                or current.assignment_rows
                or current.admissions
                or current.attempts
                or current.observed_groups
            ):
                raise ContinuousIntegrityError("ORIGINAL_ACCOUNT_PREFIX_MISSING")
            if snapshot.tables[applied_reconciliation_commits.name]:
                raise ContinuousIntegrityError("ORIGINAL_RECONCILIATION_PARENT_MISSING")
            return None
        through = self.account.resolve_index(raw)
        if through.receipt.commit.sequence != len(expected):
            raise ContinuousIntegrityError("COMPLETE_ACCOUNT_PREFIX_INVENTORY_DIFFERS")
        previous: ResolvedContinuousAccount | None = None
        admissions: set[str] = set()
        observed: set[str] = set()
        paired: set[str] = set()
        while (
            previous is None or previous.receipt.commit.sequence < through.receipt.commit.sequence
        ):
            with _repeatable_read_transaction(self.engine) as connection:
                page = self.account.capture_page_in_transaction(
                    connection, through=through, after=previous
                )
            for row in page:
                index = self.account.resolve_index(row, previous=previous)
                objects.inspect(index.receipt.commit)
                with _repeatable_read_transaction(self.engine) as connection:
                    captured = self.account.capture_snapshot_in_transaction(connection, index=index)
                actual = self.account.resolve_snapshot(captured, previous=previous)
                self.account.require_resolved(actual)
                objects.inspect(actual)
                evidence = self.composer.inspect_resolved_evidence(actual.composition)
                for reference in evidence.admissions:
                    if reference.command_id in admissions:
                        raise ContinuousIntegrityError(
                            "DAILY_ADMISSION_HAS_MULTIPLE_ACCOUNT_PARENTS"
                        )
                    admissions.add(reference.command_id)
                if evidence.observed_holds is not None:
                    observed.add(evidence.observed_holds.semantic_sha256)
                pair = self.publisher.resolve_for_account(actual, scope=self.reconciliation_scope)
                if pair is not None:
                    self.publisher.require_resolved(pair)
                    paired.add(pair.reconciliation.receipt.commit.command_id)
                    with _repeatable_read_transaction(self.engine) as connection:
                        self.publisher.recheck_in_transaction(
                            connection, pair, fence=self.fence, require_current=False
                        )
                with _repeatable_read_transaction(self.engine) as connection:
                    self.account.recheck_in_transaction(connection, actual, require_current=False)
                previous = actual
        assert previous is not None
        if admissions != {
            row["command_id"] for row in snapshot.tables[daily_runtime_admissions.name]
        }:
            raise ContinuousIntegrityError("DAILY_ADMISSION_ACCOUNT_COVERAGE_DIFFERS")
        if observed != {group.semantic_sha256 for group in current.observed_groups}:
            raise ContinuousIntegrityError("DAILY_OBSERVED_ACCOUNT_COVERAGE_DIFFERS")
        if paired != {
            row["command_id"] for row in snapshot.tables[applied_reconciliation_commits.name]
        }:
            raise ContinuousIntegrityError("APPLIED_ACCOUNT_PAIR_COVERAGE_DIFFERS")
        final = previous.receipt.commit.transition.resulting_heads
        if (
            tuple(binding.commitment for binding in current.obligations.bindings)
            != tuple(
                sorted(previous.checkpoint.state.commitments, key=lambda item: item.commitment_id)
            )
            or final.capacity_sha256 != current.obligations.semantic_sha256
            or final.attempt_sha256 != daily_attempt_inventory_sha256(current.attempts)
            or final.effect_watermark
            != daily_runtime_effect_watermark(
                attempt_envelopes=current.attempt_envelopes,
                observed_groups=current.observed_groups,
            )
        ):
            raise ContinuousIntegrityError("FINAL_CANONICAL_DAILY_ACCOUNT_HEADS_DIFFER")
        return previous
