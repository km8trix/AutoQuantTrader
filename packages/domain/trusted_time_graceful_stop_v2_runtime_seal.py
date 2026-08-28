"""Process/thread/fork-bound in-memory seals for injected lifecycle-v2 values.

These seals are deliberately non-durable and grant no production authority.
They prevent ordinary Python value copying, mutation, replay, and fork/thread
transfer from turning an already validated injected value into different
success evidence.  Milestone two must replace injected observer provenance
with the reviewed native owners; it must not serialize or adapt these seals.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace

_REGISTER_AT_FORK = getattr(os, "register_at_fork", None)


@dataclass(frozen=True, slots=True)
class RuntimeSealMetadata:
    provenance: str
    scope_sha256: str
    origin_pid: int
    origin_thread: threading.Thread
    fork_epoch: object


@dataclass(frozen=True, slots=True)
class _RuntimeSealEntry:
    value: object
    snapshot_sha256: str
    kind: str
    metadata: RuntimeSealMetadata
    consumed: bool = False
    actions: frozenset[str] = frozenset()


class LifecycleV2RuntimeSealRegistry:
    """Strong-reference registry for one injected lifecycle-v2 trust domain."""

    __slots__ = (
        "_current_thread",
        "_entries",
        "_fork_epoch",
        "_fork_invalidated",
        "_getpid",
        "_lock",
        "_origin_fork_epoch",
        "_origin_pid",
    )

    def __init__(
        self,
        *,
        _getpid: Callable[[], int] = os.getpid,
        _current_thread: Callable[[], threading.Thread] = threading.current_thread,
        _rlock: Callable[[], threading.RLock] = threading.RLock,
        _register_at_fork: Callable[..., None] | None = _REGISTER_AT_FORK,
    ) -> None:
        self._entries: dict[int, _RuntimeSealEntry] = {}
        self._getpid = _getpid
        self._current_thread = _current_thread
        self._lock = _rlock()
        self._origin_pid = _getpid()
        self._fork_epoch = object()
        self._origin_fork_epoch = self._fork_epoch
        self._fork_invalidated = False
        if _register_at_fork is not None:
            registry = self

            def invalidate_in_child() -> None:
                registry._fork_invalidated = True
                registry._fork_epoch = object()

            _register_at_fork(after_in_child=invalidate_in_child)

    def _registry_is_current(self) -> bool:
        return (
            not self._fork_invalidated
            and self._origin_pid == self._getpid()
            and self._fork_epoch is self._origin_fork_epoch
        )

    def _entry_is_current(self, entry: _RuntimeSealEntry) -> bool:
        metadata = entry.metadata
        return (
            metadata.origin_pid == self._getpid()
            and metadata.origin_thread is self._current_thread()
            and metadata.fork_epoch is self._fork_epoch
        )

    def seal(
        self,
        value: object,
        *,
        snapshot_sha256: str,
        kind: str,
        provenance: str,
        scope_sha256: str,
    ) -> bool:
        if not self._registry_is_current():
            return False
        key = id(value)
        with self._lock:
            if key in self._entries:
                return False
            self._entries[key] = _RuntimeSealEntry(
                value=value,
                snapshot_sha256=snapshot_sha256,
                kind=kind,
                metadata=RuntimeSealMetadata(
                    provenance=provenance,
                    scope_sha256=scope_sha256,
                    origin_pid=self._getpid(),
                    origin_thread=self._current_thread(),
                    fork_epoch=self._fork_epoch,
                ),
            )
        return True

    def require(
        self,
        value: object,
        *,
        snapshot_sha256: str,
        kind: str,
        provenance: str | None = None,
        scope_sha256: str | None = None,
        allow_consumed: bool = True,
    ) -> RuntimeSealMetadata | None:
        if not self._registry_is_current():
            return None
        with self._lock:
            entry = self._entries.get(id(value))
            if (
                entry is None
                or entry.value is not value
                or entry.kind != kind
                or entry.snapshot_sha256 != snapshot_sha256
                or not self._entry_is_current(entry)
                or (entry.consumed and not allow_consumed)
                or (provenance is not None and entry.metadata.provenance != provenance)
                or (scope_sha256 is not None and entry.metadata.scope_sha256 != scope_sha256)
            ):
                return None
            return entry.metadata

    def consume(
        self,
        value: object,
        *,
        snapshot_sha256: str,
        kind: str,
        provenance: str | None = None,
        scope_sha256: str | None = None,
    ) -> RuntimeSealMetadata | None:
        if not self._registry_is_current():
            return None
        with self._lock:
            entry = self._entries.get(id(value))
            if (
                entry is None
                or entry.value is not value
                or entry.kind != kind
                or entry.snapshot_sha256 != snapshot_sha256
                or entry.consumed
                or not self._entry_is_current(entry)
                or (provenance is not None and entry.metadata.provenance != provenance)
                or (scope_sha256 is not None and entry.metadata.scope_sha256 != scope_sha256)
            ):
                return None
            self._entries[id(value)] = replace(entry, consumed=True)
            return entry.metadata

    def transition(
        self,
        source: object,
        *,
        source_snapshot_sha256: str,
        result: object,
        result_snapshot_sha256: str,
        kind: str,
        provenance: str,
        scope_sha256: str,
    ) -> bool:
        if not self._registry_is_current():
            return False
        with self._lock:
            source_entry = self._entries.get(id(source))
            if (
                source_entry is None
                or source_entry.value is not source
                or source_entry.kind != kind
                or source_entry.snapshot_sha256 != source_snapshot_sha256
                or source_entry.consumed
                or not self._entry_is_current(source_entry)
                or source_entry.metadata.provenance != provenance
                or source_entry.metadata.scope_sha256 != scope_sha256
                or id(result) in self._entries
            ):
                return False
            self._entries[id(source)] = replace(source_entry, consumed=True)
            self._entries[id(result)] = _RuntimeSealEntry(
                value=result,
                snapshot_sha256=result_snapshot_sha256,
                kind=kind,
                metadata=RuntimeSealMetadata(
                    provenance=provenance,
                    scope_sha256=scope_sha256,
                    origin_pid=self._getpid(),
                    origin_thread=self._current_thread(),
                    fork_epoch=self._fork_epoch,
                ),
            )
            return True

    def consume_action(
        self,
        value: object,
        *,
        snapshot_sha256: str,
        kind: str,
        action: str,
        prerequisites: frozenset[str] = frozenset(),
    ) -> RuntimeSealMetadata | None:
        if not self._registry_is_current():
            return None
        with self._lock:
            entry = self._entries.get(id(value))
            if (
                entry is None
                or entry.value is not value
                or entry.kind != kind
                or entry.snapshot_sha256 != snapshot_sha256
                or entry.consumed
                or action in entry.actions
                or not prerequisites.issubset(entry.actions)
                or not self._entry_is_current(entry)
            ):
                return None
            self._entries[id(value)] = replace(entry, actions=entry.actions | {action})
            return entry.metadata

    def finalize_actions(
        self,
        value: object,
        *,
        snapshot_sha256: str,
        kind: str,
        required_actions: frozenset[str],
    ) -> RuntimeSealMetadata | None:
        if not self._registry_is_current():
            return None
        with self._lock:
            entry = self._entries.get(id(value))
            if (
                entry is None
                or entry.value is not value
                or entry.kind != kind
                or entry.snapshot_sha256 != snapshot_sha256
                or entry.consumed
                or entry.actions != required_actions
                or not self._entry_is_current(entry)
            ):
                return None
            self._entries[id(value)] = replace(entry, consumed=True)
            return entry.metadata


__all__ = ["LifecycleV2RuntimeSealRegistry", "RuntimeSealMetadata"]
