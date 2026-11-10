"""One independently owned, readiness-gated selection metadata reader.

The returned snapshot retains its original row-integrity-only meaning. The
preceding owner proof and separate read transaction are not atomic financial
authorization. This component never starts, stops or renews its original owner.
"""

from __future__ import annotations

from _thread import LockType
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Literal
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.pool import NullPool

from apps.trader.continuous_readiness_owner import (
    ContinuousReadinessOwner,
    ReadinessCheckResult,
    ReadinessOwnerStatus,
)
from apps.trader.continuous_simulation_factory import _existing_private
from apps.trader.readiness_store_binding import ReadinessStoreBinding, _StoreBindingValues
from apps.trader.synthetic_session_genesis import _database_path
from packages.domain.continuous_selection_contracts import (
    ContinuousSelectionCheckpoint,
    ContinuousSelectionSnapshot,
    RetainedContinuousSelection,
)
from packages.persistence.continuous_selection_read_model import SqlContinuousSelectionReadModel

_OWNER = ContinuousReadinessOwner
_OWNER_BINDING = ContinuousReadinessOwner.store_binding
_OWNER_CHECK = ContinuousReadinessOwner.check
_OWNER_STATUS = ContinuousReadinessOwner.status
_BINDING = ReadinessStoreBinding
_BINDING_VALIDATE = ReadinessStoreBinding.__post_init__
_READER = SqlContinuousSelectionReadModel
_READ = SqlContinuousSelectionReadModel.read
_ENGINE = sa.Engine
_CONNECT = sa.Engine.connect
_DISPOSE = sa.Engine.dispose
_POOL_DISPOSE = NullPool.dispose
_POOL_RECREATE = NullPool.recreate
_LOCK = type(Lock())
_SNAPSHOT_VALIDATE = ContinuousSelectionSnapshot.__post_init__
type _OriginalGraph = tuple[
    ContinuousReadinessOwner,
    sa.Engine,
    SqlContinuousSelectionReadModel,
    sa.URL,
    NullPool,
    LockType,
    _StoreBindingValues,
]


@dataclass(frozen=True, slots=True)
class ReadinessReadStoreStatus:
    phase: Literal["open", "closing", "closed"]
    busy: bool
    cleanup_complete: bool
    cleanup_failure: Literal["cleanup_failed"] | None


def _native_values(values: object) -> _StoreBindingValues:
    if (
        type(values) is not tuple
        or len(values) != 8
        or any(type(values[index]) is not str for index in (0, 1, 2, 3, 4, 7))
        or type(values[5]) is not int
        or type(values[6]) is not int
    ):
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    try:
        _BINDING_VALIDATE(_BINDING(*values))
    except Exception:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED") from None
    return (values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7])


def _binding_values(value: object) -> _StoreBindingValues:
    if type(value) is not ReadinessStoreBinding:
        raise RuntimeError("READINESS_READ_STORE_UNAVAILABLE")
    return _native_values(
        (
            value.incarnation,
            value.account_id,
            value.account_binding_sha256,
            value.stream_id,
            value.database_path,
            value.database_device,
            value.database_inode,
            value.configuration_payload_sha256,
        )
    )


def _owner_bindings(owner: ContinuousReadinessOwner) -> None:
    if type(owner) is not _OWNER:
        raise ValueError("READINESS_READ_STORE_OWNER_REQUIRED")
    for name, original in (
        ("store_binding", _OWNER_BINDING),
        ("check", _OWNER_CHECK),
        ("status", _OWNER_STATUS),
    ):
        if vars(_OWNER).get(name) is not original or name in vars(owner):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")


def _engine_bindings(engine: sa.Engine) -> None:
    if type(engine) is not _ENGINE:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    for name, original in (("connect", _CONNECT), ("dispose", _DISPOSE)):
        if vars(_ENGINE).get(name) is not original or name in vars(engine):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")


def _pool_bindings(pool: NullPool) -> None:
    if type(pool) is not NullPool:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    for name, original in (("dispose", _POOL_DISPOSE), ("recreate", _POOL_RECREATE)):
        if vars(NullPool).get(name) is not original or name in vars(pool):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")


def _dispose_owned(
    engine: sa.Engine, pool: NullPool
) -> tuple[BaseException | None, BaseException | None]:
    """Quiescent cleanup of the retained pool, never a replacement pool.

    Only these finite method bindings are checked. If the two pool methods are
    changed, the saved original pool disposer is the sole safe fallback; that
    is not a returned Engine disposal and must remain cleanup-incomplete.
    """
    guard: BaseException | None = None
    try:
        _engine_bindings(engine)
        if engine.pool is not pool:
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    except BaseException as error:
        guard = error
    safe_pool = True
    try:
        _pool_bindings(pool)
    except BaseException as error:
        safe_pool = False
        if guard is None:
            guard = error
    try:
        # Reselect only our independently retained resource, after all work ends.
        # Saved Engine.dispose would otherwise invoke a foreign current pool.
        engine.pool = pool
        if safe_pool:
            _DISPOSE(engine)
        else:
            _POOL_DISPOSE(pool)
            return guard, RuntimeError("READINESS_READ_STORE_CLEANUP_INCOMPLETE")
    except BaseException as cleanup:
        return guard, cleanup
    return guard, None


def _physical(values: _StoreBindingValues, engine: sa.Engine) -> None:
    try:
        path = _existing_private(values[4], directory=False)
        before = path.lstat()
        if (before.st_dev, before.st_ino) != (values[5], values[6]):
            raise ValueError("identity")
        _engine_bindings(engine)
        if _database_path(engine) != path:
            raise ValueError("identity")
        _engine_bindings(engine)
        after = _existing_private(values[4], directory=False).lstat()
        if (after.st_dev, after.st_ino) != (values[5], values[6]):
            raise ValueError("identity")
    except Exception:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED") from None


def _snapshot(value: object, values: _StoreBindingValues) -> ContinuousSelectionSnapshot:
    if type(value) is not ContinuousSelectionSnapshot:
        raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
    if any(type(item) is not str for item in (value.account_id, value.state, value.verification)):
        raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
    checkpoint, selection = value.checkpoint, value.selection
    if checkpoint is not None and (
        type(checkpoint) is not ContinuousSelectionCheckpoint
        or type(checkpoint.stream_id) is not str
        or type(checkpoint.sequence) is not int
        or type(checkpoint.recorded_at) is not datetime
        or type(checkpoint.recorded_at.tzinfo) is not timezone
    ):
        raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
    if selection is not None and (
        type(selection) is not RetainedContinuousSelection
        or type(selection.generation) is not int
        or any(
            type(item) is not str
            for item in (
                selection.strategy_name,
                selection.strategy_version,
                selection.configuration_sha256,
                selection.policy_id,
            )
        )
        or type(selection.enabled_for_new_exposure) is not bool
        or type(selection.live_authorized) is not bool
        or type(selection.instrument_symbols) is not tuple
        or not 1 <= len(selection.instrument_symbols) <= 4
        or any(
            type(item) is not tuple or len(item) != 2 or any(type(part) is not str for part in item)
            for item in selection.instrument_symbols
        )
        or type(selection.recorded_at) is not datetime
        or type(selection.recorded_at.tzinfo) is not timezone
        or type(selection.effective_at) is not datetime
        or type(selection.effective_at.tzinfo) is not timezone
    ):
        raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
    try:
        _SNAPSHOT_VALIDATE(value)
    except Exception:
        raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID") from None
    if value.account_id != values[1] or (
        checkpoint is not None and checkpoint.stream_id != values[3]
    ):
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    return value


def _workflow_bindings(store: ReadinessReadStore) -> None:
    if type(store) is not _STORE_CLASS:
        raise ValueError("READINESS_READ_STORE_ORIGINAL_REQUIRED")
    for name, original in _WORKFLOW_METHODS:
        if vars(_STORE_CLASS).get(name) is not original or name in vars(store):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")


def _raise_failures(errors: list[BaseException]) -> None:
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("READINESS_READ_STORE_OPERATION_AND_CLEANUP_FAILED", errors)


class ReadinessReadStore:
    """One complete synchronous body; close cannot outlive its ownership slot."""

    _identity: ReadinessReadStore
    _owner: ContinuousReadinessOwner
    _engine: sa.Engine
    _reader: SqlContinuousSelectionReadModel
    _binding: _StoreBindingValues
    _lock: LockType
    _original: _OriginalGraph
    _busy: bool
    _closing: bool
    _dispose_started: bool
    _dispose_finished: bool
    _cleanup_failed: bool
    _cleanup_error: BaseException | None

    def __init__(self) -> None:
        raise ValueError("READINESS_READ_STORE_OPENER_REQUIRED")

    def _require_self(self) -> None:
        if type(self) is not ReadinessReadStore or self._identity is not self:
            raise ValueError("READINESS_READ_STORE_ORIGINAL_REQUIRED")
        if (
            type(self._original) is not tuple
            or len(self._original) != 7
            or type(self._original[5]) is not _LOCK
            or self._lock is not self._original[5]
        ):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")

    def _state(self) -> None:
        if any(
            type(value) is not bool
            for value in (
                self._busy,
                self._closing,
                self._dispose_started,
                self._dispose_finished,
                self._cleanup_failed,
            )
        ):
            raise RuntimeError("READINESS_READ_STORE_STATE_INVALID")
        if (
            (self._dispose_started and (not self._closing or self._busy))
            or (self._dispose_finished and not self._dispose_started)
            or (self._cleanup_failed and not self._dispose_finished)
        ):
            raise RuntimeError("READINESS_READ_STORE_STATE_INVALID")

    def _graph(self) -> None:
        _REQUIRE_SELF(self)
        _workflow_bindings(self)
        owner, engine, reader, url, pool, _lock, values = self._original
        if (
            self._owner is not owner
            or self._engine is not engine
            or self._reader is not reader
            or type(engine) is not _ENGINE
            or type(reader) is not _READER
            or reader.engine is not engine
            or engine.url is not url
            or engine.pool is not pool
            or type(pool) is not NullPool
        ):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
        _owner_bindings(owner)
        _engine_bindings(engine)
        _pool_bindings(pool)
        if vars(_READER).get("read") is not _READ or "read" in vars(reader):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
        # Revalidate before equality: malformed leaves cannot run operators.
        if _native_values(self._binding) != _native_values(values):
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")

    def _bookend(self) -> None:
        _GRAPH(self)
        owner, engine, _reader, _url, _pool, _lock, values = self._original
        if _binding_values(_OWNER_BINDING(owner)) != values:
            raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
        _physical(values, engine)
        _GRAPH(self)

    def _perform_read(self) -> ContinuousSelectionSnapshot:
        _BOOKEND(self)
        request_id = uuid4().hex
        if type(request_id) is not str or len(request_id) != 32:
            raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
        result = _OWNER_CHECK(self._owner, request_id)
        if (
            type(result) is not ReadinessCheckResult
            or any(
                type(value) is not str
                for value in (result.status, result.reason, result.request_id, result.incarnation)
            )
            or result.request_id != request_id
            or result.incarnation != self._binding[0]
            or result.status != "ready"
            or result.reason != "verified"
        ):
            raise RuntimeError("READINESS_READ_STORE_UNAVAILABLE")
        _BOOKEND(self)
        value = _snapshot(_READ(self._reader, self._binding[1]), self._binding)
        _BOOKEND(self)
        observed = _OWNER_STATUS(self._owner)
        if (
            type(observed) is not ReadinessOwnerStatus
            or any(type(value) is not str for value in (observed.phase, observed.incarnation))
            or any(type(value) is not bool for value in (observed.busy, observed.cleanup_complete))
            or (observed.primary_failure is not None and type(observed.primary_failure) is not str)
            or (observed.cleanup_failure is not None and type(observed.cleanup_failure) is not str)
            or observed.incarnation != self._binding[0]
            or observed.phase != "idle"
            or observed.busy is not False
            or observed.cleanup_complete is not False
            or observed.primary_failure is not None
            or observed.cleanup_failure is not None
        ):
            raise RuntimeError("READINESS_READ_STORE_UNAVAILABLE")
        _GRAPH(self)
        return value

    def _status(self) -> ReadinessReadStoreStatus:
        _STATE(self)
        phase: Literal["open", "closing", "closed"] = (
            "closed" if self._dispose_finished else "closing" if self._closing else "open"
        )
        return ReadinessReadStoreStatus(
            phase,
            self._busy,
            self._dispose_finished and not self._cleanup_failed,
            "cleanup_failed" if self._cleanup_failed else None,
        )

    def status(self) -> ReadinessReadStoreStatus:
        _REQUIRE_SELF(self)
        with self._lock:
            return _STATUS(self)

    def _elect_disposal(self) -> bool:
        if self._closing and not self._busy and not self._dispose_started:
            self._dispose_started = True
            return True
        return False

    def _dispose_original(self) -> tuple[BaseException | None, BaseException | None]:
        engine = self._original[1]
        pool = self._original[4]
        guard, cleanup = _dispose_owned(engine, pool)
        with self._lock:
            self._cleanup_error = cleanup
            self._cleanup_failed = cleanup is not None
            self._dispose_finished = True
        return guard, cleanup

    def read(self) -> ContinuousSelectionSnapshot:
        _REQUIRE_SELF(self)
        with self._lock:
            _STATE(self)
            if self._closing:
                raise RuntimeError("READINESS_READ_STORE_CLOSED")
            if self._busy:
                raise RuntimeError("READINESS_READ_STORE_BUSY")
            self._busy = True
        errors: list[BaseException] = []
        value: ContinuousSelectionSnapshot | None = None
        try:
            value = _PERFORM_READ(self)
        except BaseException as error:
            errors.append(error)
        finally:
            with self._lock:
                dispose = False
                try:
                    _STATE(self)
                except BaseException as error:
                    # Unknown state cannot authorize an extra disposal attempt.
                    errors.append(error)
                    self._busy = False
                else:
                    self._busy = False
                    dispose = _ELECT_DISPOSAL(self)
                    if dispose and not errors:
                        errors.append(RuntimeError("READINESS_READ_STORE_CLOSED"))
            if dispose:
                guard, cleanup = _DISPOSE_ORIGINAL(self)
                errors.extend(error for error in (guard, cleanup) if error is not None)
        _raise_failures(errors)
        if value is None:
            raise RuntimeError("READINESS_READ_STORE_RESULT_INVALID")
        return value

    def close(self) -> ReadinessReadStoreStatus:
        _REQUIRE_SELF(self)
        with self._lock:
            _STATE(self)
            self._closing = True
            dispose = _ELECT_DISPOSAL(self)
        if dispose:
            guard, cleanup = _DISPOSE_ORIGINAL(self)
            if guard is not None:
                _raise_failures([guard] + ([cleanup] if cleanup is not None else []))
        _REQUIRE_SELF(self)
        with self._lock:
            return _STATUS(self)


_STORE_CLASS = ReadinessReadStore
_REQUIRE_SELF = ReadinessReadStore._require_self
_STATE = ReadinessReadStore._state
_GRAPH = ReadinessReadStore._graph
_BOOKEND = ReadinessReadStore._bookend
_PERFORM_READ = ReadinessReadStore._perform_read
_STATUS = ReadinessReadStore._status
_ELECT_DISPOSAL = ReadinessReadStore._elect_disposal
_DISPOSE_ORIGINAL = ReadinessReadStore._dispose_original
_WORKFLOW_METHODS = (
    ("_require_self", _REQUIRE_SELF),
    ("_state", _STATE),
    ("_graph", _GRAPH),
    ("_bookend", _BOOKEND),
    ("_perform_read", _PERFORM_READ),
    ("_status", _STATUS),
    ("_elect_disposal", _ELECT_DISPOSAL),
    ("_dispose_original", _DISPOSE_ORIGINAL),
)


def open_readiness_read_store(owner: ContinuousReadinessOwner) -> ReadinessReadStore:
    """Open an independent existing-mode read Engine; never start the owner."""
    _owner_bindings(owner)
    values = _binding_values(_OWNER_BINDING(owner))
    # This is an explicit lifecycle operation, not data-only app construction.
    try:
        path = _existing_private(values[4], directory=False)
        before = path.lstat()
        if (before.st_dev, before.st_ino) != (values[5], values[6]):
            raise ValueError("identity")
    except Exception:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED") from None
    url = sa.URL.create(
        "sqlite+pysqlite",
        database=Path(values[4]).as_uri(),
        query={"mode": "ro", "uri": "true"},
    )
    engine = sa.create_engine(url, poolclass=NullPool, connect_args={"timeout": 0.1})
    if type(engine) is not _ENGINE:
        raise RuntimeError("READINESS_READ_STORE_BINDING_CHANGED")
    pool = engine.pool
    if type(pool) is not NullPool:
        # No known-owned original pool was returned: never invoke a foreign one.
        raise BaseExceptionGroup(
            "READINESS_READ_STORE_OPERATION_AND_CLEANUP_FAILED",
            [
                RuntimeError("READINESS_READ_STORE_BINDING_CHANGED"),
                RuntimeError("READINESS_READ_STORE_CLEANUP_INCOMPLETE"),
            ],
        )
    try:
        _engine_bindings(engine)
        _pool_bindings(pool)
        reader = _READER(engine)
        store = object.__new__(ReadinessReadStore)
        store._identity = store
        store._owner, store._engine, store._reader = owner, engine, reader
        store._binding = values
        store._lock = Lock()
        store._original = (owner, engine, reader, engine.url, pool, store._lock, values)
        store._busy = store._closing = False
        store._dispose_started = store._dispose_finished = store._cleanup_failed = False
        store._cleanup_error = None
        _BOOKEND(store)
        return store
    except BaseException as primary:
        guard, cleanup = _dispose_owned(engine, pool)
        errors = [primary]
        errors.extend(error for error in (guard, cleanup) if error is not None)
        _raise_failures(errors)
        raise
