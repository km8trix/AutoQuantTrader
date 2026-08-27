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
from dataclasses import dataclass, replace

_FORK_EPOCH = object()


def _after_fork_in_child() -> None:
    global _FORK_EPOCH
    _FORK_EPOCH = object()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


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

    __slots__ = ("_entries", "_fork_epoch", "_lock", "_origin_pid")

    def __init__(self) -> None:
        self._entries: dict[int, _RuntimeSealEntry] = {}
        self._lock = threading.RLock()
        self._origin_pid = os.getpid()
        self._fork_epoch = _FORK_EPOCH

    def _registry_is_current(self) -> bool:
        return self._origin_pid == os.getpid() and self._fork_epoch is _FORK_EPOCH

    @staticmethod
    def _entry_is_current(entry: _RuntimeSealEntry) -> bool:
        metadata = entry.metadata
        return (
            metadata.origin_pid == os.getpid()
            and metadata.origin_thread is threading.current_thread()
            and metadata.fork_epoch is _FORK_EPOCH
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
                    origin_pid=os.getpid(),
                    origin_thread=threading.current_thread(),
                    fork_epoch=_FORK_EPOCH,
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
                    origin_pid=os.getpid(),
                    origin_thread=threading.current_thread(),
                    fork_epoch=_FORK_EPOCH,
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
