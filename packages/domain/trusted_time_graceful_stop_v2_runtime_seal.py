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
from typing import TYPE_CHECKING, Any

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


def _install_lifecycle_v2_runtime_seal_registry() -> type[object]:
    """Capture every authority-bearing dependency outside mutable module globals."""

    entry_type = _RuntimeSealEntry
    metadata_type = RuntimeSealMetadata
    replace_entry = replace
    identity = id
    new_epoch = object
    default_getpid = os.getpid
    default_current_thread = threading.current_thread
    default_rlock = threading.RLock
    default_register_at_fork = _REGISTER_AT_FORK

    def registry_is_current(registry: Any) -> bool:
        return (
            not registry._fork_invalidated
            and registry._origin_pid == registry._getpid()
            and registry._fork_epoch is registry._origin_fork_epoch
        )

    def entry_is_current(registry: Any, entry: _RuntimeSealEntry) -> bool:
        metadata = entry.metadata
        return (
            metadata.origin_pid == registry._getpid()
            and metadata.origin_thread is registry._current_thread()
            and metadata.fork_epoch is registry._fork_epoch
        )

    class _LifecycleV2RuntimeSealRegistry:
        """Strong-reference registry for one injected lifecycle-v2 trust domain."""

        __slots__ = (
            "__dict__",
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
            _getpid: Callable[[], int] = default_getpid,
            _current_thread: Callable[[], threading.Thread] = default_current_thread,
            _rlock: Callable[[], threading.RLock] = default_rlock,
            _register_at_fork: Callable[..., None] | None = default_register_at_fork,
        ) -> None:
            self._entries: dict[int, _RuntimeSealEntry] = {}
            self._getpid = _getpid
            self._current_thread = _current_thread
            self._lock = _rlock()
            self._origin_pid = _getpid()
            self._fork_epoch = new_epoch()
            self._origin_fork_epoch = self._fork_epoch
            self._fork_invalidated = False
            if _register_at_fork is not None:
                registry = self

                def invalidate_in_child() -> None:
                    registry._fork_invalidated = True
                    registry._fork_epoch = new_epoch()

                _register_at_fork(after_in_child=invalidate_in_child)
            self.__dict__.update(
                {
                    "_entry_is_current": self._entry_is_current,
                    "_registry_is_current": self._registry_is_current,
                    "consume": self.consume,
                    "consume_action": self.consume_action,
                    "finalize_actions": self.finalize_actions,
                    "require": self.require,
                    "seal": self.seal,
                    "transition": self.transition,
                }
            )

        def _registry_is_current(self) -> bool:
            return registry_is_current(self)

        def _entry_is_current(self, entry: _RuntimeSealEntry) -> bool:
            return entry_is_current(self, entry)

        def seal(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            provenance: str,
            scope_sha256: str,
        ) -> bool:
            if not registry_is_current(self):
                return False
            key = identity(value)
            with self._lock:
                if key in self._entries:
                    return False
                self._entries[key] = entry_type(
                    value=value,
                    snapshot_sha256=snapshot_sha256,
                    kind=kind,
                    metadata=metadata_type(
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
            if not registry_is_current(self):
                return None
            with self._lock:
                entry = self._entries.get(identity(value))
                if (
                    entry is None
                    or entry.value is not value
                    or entry.kind != kind
                    or entry.snapshot_sha256 != snapshot_sha256
                    or not entry_is_current(self, entry)
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
            if not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = self._entries.get(key)
                if (
                    entry is None
                    or entry.value is not value
                    or entry.kind != kind
                    or entry.snapshot_sha256 != snapshot_sha256
                    or entry.consumed
                    or not entry_is_current(self, entry)
                    or (provenance is not None and entry.metadata.provenance != provenance)
                    or (scope_sha256 is not None and entry.metadata.scope_sha256 != scope_sha256)
                ):
                    return None
                self._entries[key] = replace_entry(entry, consumed=True)
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
            if not registry_is_current(self):
                return False
            with self._lock:
                source_key = identity(source)
                result_key = identity(result)
                source_entry = self._entries.get(source_key)
                if (
                    source_entry is None
                    or source_entry.value is not source
                    or source_entry.kind != kind
                    or source_entry.snapshot_sha256 != source_snapshot_sha256
                    or source_entry.consumed
                    or not entry_is_current(self, source_entry)
                    or source_entry.metadata.provenance != provenance
                    or source_entry.metadata.scope_sha256 != scope_sha256
                    or result_key in self._entries
                ):
                    return False
                self._entries[source_key] = replace_entry(source_entry, consumed=True)
                self._entries[result_key] = entry_type(
                    value=result,
                    snapshot_sha256=result_snapshot_sha256,
                    kind=kind,
                    metadata=metadata_type(
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
            if not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = self._entries.get(key)
                if (
                    entry is None
                    or entry.value is not value
                    or entry.kind != kind
                    or entry.snapshot_sha256 != snapshot_sha256
                    or entry.consumed
                    or action in entry.actions
                    or not prerequisites.issubset(entry.actions)
                    or not entry_is_current(self, entry)
                ):
                    return None
                self._entries[key] = replace_entry(
                    entry,
                    actions=entry.actions | {action},
                )
                return entry.metadata

        def finalize_actions(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            required_actions: frozenset[str],
        ) -> RuntimeSealMetadata | None:
            if not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = self._entries.get(key)
                if (
                    entry is None
                    or entry.value is not value
                    or entry.kind != kind
                    or entry.snapshot_sha256 != snapshot_sha256
                    or entry.consumed
                    or entry.actions != required_actions
                    or not entry_is_current(self, entry)
                ):
                    return None
                self._entries[key] = replace_entry(entry, consumed=True)
                return entry.metadata

    _LifecycleV2RuntimeSealRegistry.__name__ = "LifecycleV2RuntimeSealRegistry"
    _LifecycleV2RuntimeSealRegistry.__qualname__ = "LifecycleV2RuntimeSealRegistry"
    return _LifecycleV2RuntimeSealRegistry


if TYPE_CHECKING:

    class LifecycleV2RuntimeSealRegistry:
        def __init__(
            self,
            *,
            _getpid: Callable[[], int] = ...,
            _current_thread: Callable[[], threading.Thread] = ...,
            _rlock: Callable[[], threading.RLock] = ...,
            _register_at_fork: Callable[..., None] | None = ...,
        ) -> None: ...

        def _registry_is_current(self) -> bool: ...

        def _entry_is_current(self, entry: _RuntimeSealEntry) -> bool: ...

        def seal(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            provenance: str,
            scope_sha256: str,
        ) -> bool: ...

        def require(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            provenance: str | None = None,
            scope_sha256: str | None = None,
            allow_consumed: bool = True,
        ) -> RuntimeSealMetadata | None: ...

        def consume(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            provenance: str | None = None,
            scope_sha256: str | None = None,
        ) -> RuntimeSealMetadata | None: ...

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
        ) -> bool: ...

        def consume_action(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            action: str,
            prerequisites: frozenset[str] = frozenset(),
        ) -> RuntimeSealMetadata | None: ...

        def finalize_actions(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            required_actions: frozenset[str],
        ) -> RuntimeSealMetadata | None: ...

else:
    LifecycleV2RuntimeSealRegistry = _install_lifecycle_v2_runtime_seal_registry()
del _install_lifecycle_v2_runtime_seal_registry


def _install_lifecycle_v2_runtime_seal_bootstrap_claim() -> Callable[..., object]:
    metadata_type = RuntimeSealMetadata
    registry_type = LifecycleV2RuntimeSealRegistry

    def claim_runtime_seal_bootstrap(
        permit: object,
        claim: Callable[[object, type[RuntimeSealMetadata], type[object]], object],
    ) -> object:
        return claim(permit, metadata_type, registry_type)

    return claim_runtime_seal_bootstrap


_claim_lifecycle_v2_runtime_seal_bootstrap = (
    _install_lifecycle_v2_runtime_seal_bootstrap_claim()
)
del _install_lifecycle_v2_runtime_seal_bootstrap_claim
globals().pop("_REGISTER_AT_FORK", None)
globals().pop("replace", None)


__all__ = ["LifecycleV2RuntimeSealRegistry", "RuntimeSealMetadata"]
