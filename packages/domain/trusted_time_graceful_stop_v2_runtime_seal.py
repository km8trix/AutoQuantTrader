"""Process/thread/fork-bound in-memory seals for injected lifecycle-v2 values.

These seals are deliberately non-durable and grant no production authority.
They prevent ordinary Python value copying, mutation, replay, and fork/thread
transfer from turning an already validated injected value into different
success evidence.  Milestone two must replace injected observer provenance
with the reviewed native owners; it must not serialize or adapt these seals.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NamedTuple

_REGISTER_AT_FORK = getattr(os, "register_at_fork", None)


class RuntimeSealMetadata(NamedTuple):
    provenance: str
    scope_sha256: str
    origin_pid: int
    origin_thread: threading.Thread
    fork_epoch: object


class _RuntimeSealEntry(NamedTuple):
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
    attribute_error_type = AttributeError
    exact_type = type
    replace_entry = _RuntimeSealEntry._replace
    immutable_set_type = frozenset
    identity = id
    new_epoch = object
    object_getattribute = object.__getattribute__
    object_setattr = object.__setattr__
    runtime_error_type = RuntimeError
    type_error_type = TypeError
    default_getpid = os.getpid
    default_current_thread = threading.current_thread
    default_get_call_frame = sys._getframe
    default_rlock = threading.RLock
    default_register_at_fork = _REGISTER_AT_FORK

    def find_entry(
        entries: tuple[tuple[int, _RuntimeSealEntry], ...],
        key: int,
    ) -> _RuntimeSealEntry | None:
        for entry_key, entry in entries:
            if entry_key == key:
                return entry
        return None

    def replace_stored_entry(
        entries: tuple[tuple[int, _RuntimeSealEntry], ...],
        key: int,
        replacement: _RuntimeSealEntry,
    ) -> tuple[tuple[int, _RuntimeSealEntry], ...]:
        return tuple(
            (entry_key, replacement if entry_key == key else entry)
            for entry_key, entry in entries
        )

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

    def mutation_caller_is_allowed(
        registry: Any,
        allowed_callers: frozenset[object],
    ) -> bool:
        caller = registry._get_call_frame(2)
        try:
            return caller.f_code in allowed_callers
        finally:
            del caller

    class _LifecycleV2RuntimeSealRegistry:
        """Strong-reference registry for one injected lifecycle-v2 trust domain."""

        _configuration_locked: bool
        _consume_action_callers: frozenset[object]
        _consume_callers: frozenset[object]
        _current_thread: Callable[[], threading.Thread]
        _entries: tuple[tuple[int, _RuntimeSealEntry], ...]
        _finalize_actions_callers: frozenset[object]
        _fork_epoch: object
        _fork_invalidated: bool
        _get_call_frame: Callable[[int], Any]
        _getpid: Callable[[], int]
        _lock: Any
        _origin_fork_epoch: object
        _origin_pid: int
        _seal_callers: frozenset[object]
        _transfer_callers: frozenset[object]
        _transition_callers: frozenset[object]

        __slots__ = (
            "_configuration_locked",
            "_consume_action_callers",
            "_consume_callers",
            "_current_thread",
            "_entries",
            "_finalize_actions_callers",
            "_fork_epoch",
            "_fork_invalidated",
            "_get_call_frame",
            "_getpid",
            "_lock",
            "_origin_fork_epoch",
            "_origin_pid",
            "_seal_callers",
            "_transfer_callers",
            "_transition_callers",
        )

        def __setattr__(self, name: str, value: object) -> None:
            try:
                configuration_locked = object_getattribute(
                    self,
                    "_configuration_locked",
                )
            except attribute_error_type:
                configuration_locked = False
            if configuration_locked:
                raise attribute_error_type("lifecycle-v2 runtime-seal registry is immutable")
            object_setattr(self, name, value)

        def __delattr__(self, _name: str) -> None:
            raise attribute_error_type("lifecycle-v2 runtime-seal registry is immutable")

        def __init__(
            self,
            *,
            _getpid: Callable[[], int] = default_getpid,
            _current_thread: Callable[[], threading.Thread] = default_current_thread,
            _get_call_frame: Callable[[int], Any] = default_get_call_frame,
            _rlock: Callable[[], threading.RLock] = default_rlock,
            _register_at_fork: Callable[..., None] | None = default_register_at_fork,
            _seal_callers: frozenset[object] = frozenset(),
            _transition_callers: frozenset[object] = frozenset(),
            _consume_action_callers: frozenset[object] = frozenset(),
            _finalize_actions_callers: frozenset[object] = frozenset(),
            _consume_callers: frozenset[object] = frozenset(),
            _transfer_callers: frozenset[object] = frozenset(),
        ) -> None:
            try:
                object_getattribute(self, "_configuration_locked")
            except attribute_error_type:
                pass
            else:
                raise runtime_error_type(
                    "lifecycle-v2 runtime-seal registry cannot be reinitialized"
                )
            for callers in (
                _seal_callers,
                _transition_callers,
                _consume_action_callers,
                _finalize_actions_callers,
                _consume_callers,
                _transfer_callers,
            ):
                if exact_type(callers) is not immutable_set_type:
                    raise type_error_type(
                        "lifecycle-v2 runtime-seal caller policy is not immutable"
                    )
            object_setattr(self, "_configuration_locked", False)
            object_setattr(self, "_entries", ())
            object_setattr(self, "_getpid", _getpid)
            object_setattr(self, "_current_thread", _current_thread)
            object_setattr(self, "_get_call_frame", _get_call_frame)
            object_setattr(self, "_lock", _rlock())
            object_setattr(self, "_origin_pid", _getpid())
            object_setattr(self, "_fork_epoch", new_epoch())
            object_setattr(self, "_origin_fork_epoch", self._fork_epoch)
            object_setattr(self, "_fork_invalidated", False)
            object_setattr(self, "_seal_callers", _seal_callers)
            object_setattr(self, "_transition_callers", _transition_callers)
            object_setattr(self, "_consume_action_callers", _consume_action_callers)
            object_setattr(self, "_finalize_actions_callers", _finalize_actions_callers)
            object_setattr(self, "_consume_callers", _consume_callers)
            object_setattr(self, "_transfer_callers", _transfer_callers)
            if _register_at_fork is not None:
                registry = self

                def invalidate_in_child() -> None:
                    object_setattr(registry, "_fork_invalidated", True)
                    object_setattr(registry, "_fork_epoch", new_epoch())

                _register_at_fork(after_in_child=invalidate_in_child)
            object_setattr(self, "_configuration_locked", True)

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
            if not mutation_caller_is_allowed(
                self,
                self._seal_callers,
            ) or not registry_is_current(self):
                return False
            key = identity(value)
            with self._lock:
                if find_entry(self._entries, key) is not None:
                    return False
                entries = (
                    *self._entries,
                    (
                        key,
                        entry_type(
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
                        ),
                    ),
                )
                object_setattr(self, "_entries", entries)
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
            consumed: bool | None = None,
        ) -> RuntimeSealMetadata | None:
            if not registry_is_current(self):
                return None
            with self._lock:
                entry = find_entry(self._entries, identity(value))
                if (
                    entry is None
                    or entry.value is not value
                    or entry.kind != kind
                    or entry.snapshot_sha256 != snapshot_sha256
                    or not entry_is_current(self, entry)
                    or (entry.consumed and not allow_consumed)
                    or (consumed is not None and entry.consumed is not consumed)
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
            if not mutation_caller_is_allowed(
                self,
                self._consume_callers,
            ) or not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = find_entry(self._entries, key)
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
                entries = replace_stored_entry(
                    self._entries,
                    key,
                    replace_entry(entry, consumed=True),
                )
                object_setattr(self, "_entries", entries)
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
            if not mutation_caller_is_allowed(
                self,
                self._transition_callers,
            ) or not registry_is_current(self):
                return False
            with self._lock:
                source_key = identity(source)
                result_key = identity(result)
                source_entry = find_entry(self._entries, source_key)
                if (
                    source_entry is None
                    or source_entry.value is not source
                    or source_entry.kind != kind
                    or source_entry.snapshot_sha256 != source_snapshot_sha256
                    or source_entry.consumed
                    or not entry_is_current(self, source_entry)
                    or source_entry.metadata.provenance != provenance
                    or source_entry.metadata.scope_sha256 != scope_sha256
                    or find_entry(self._entries, result_key) is not None
                ):
                    return False
                entries = (
                    *replace_stored_entry(
                        self._entries,
                        source_key,
                        replace_entry(source_entry, consumed=True),
                    ),
                    (
                        result_key,
                        entry_type(
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
                        ),
                    ),
                )
                object_setattr(self, "_entries", entries)
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
            if not mutation_caller_is_allowed(
                self,
                self._consume_action_callers,
            ) or not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = find_entry(self._entries, key)
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
                entries = replace_stored_entry(
                    self._entries,
                    key,
                    replace_entry(
                        entry,
                        actions=entry.actions | immutable_set_type((action,)),
                    ),
                )
                object_setattr(self, "_entries", entries)
                return entry.metadata

        def consume_action_and_transfer(
            self,
            source: object,
            *,
            source_snapshot_sha256: str,
            source_kind: str,
            action: str,
            result: object,
            result_snapshot_sha256: str,
            result_kind: str,
            prerequisites: frozenset[str] = frozenset(),
        ) -> RuntimeSealMetadata | None:
            """Atomically consume one source action and seal its derived result."""

            if not mutation_caller_is_allowed(
                self,
                self._transfer_callers,
            ) or not registry_is_current(self):
                return None
            with self._lock:
                source_key = identity(source)
                result_key = identity(result)
                source_entry = find_entry(self._entries, source_key)
                if (
                    source_entry is None
                    or source_entry.value is not source
                    or source_entry.kind != source_kind
                    or source_entry.snapshot_sha256 != source_snapshot_sha256
                    or source_entry.consumed
                    or action in source_entry.actions
                    or not prerequisites.issubset(source_entry.actions)
                    or not entry_is_current(self, source_entry)
                    or find_entry(self._entries, result_key) is not None
                ):
                    return None
                entries = (
                    *replace_stored_entry(
                        self._entries,
                        source_key,
                        replace_entry(
                            source_entry,
                            actions=source_entry.actions
                            | immutable_set_type((action,)),
                        ),
                    ),
                    (
                        result_key,
                        entry_type(
                            value=result,
                            snapshot_sha256=result_snapshot_sha256,
                            kind=result_kind,
                            metadata=metadata_type(
                                provenance=source_entry.metadata.provenance,
                                scope_sha256=source_entry.metadata.scope_sha256,
                                origin_pid=self._getpid(),
                                origin_thread=self._current_thread(),
                                fork_epoch=self._fork_epoch,
                            ),
                        ),
                    ),
                )
                object_setattr(self, "_entries", entries)
                return source_entry.metadata

        def finalize_actions(
            self,
            value: object,
            *,
            snapshot_sha256: str,
            kind: str,
            required_actions: frozenset[str],
        ) -> RuntimeSealMetadata | None:
            if not mutation_caller_is_allowed(
                self,
                self._finalize_actions_callers,
            ) or not registry_is_current(self):
                return None
            with self._lock:
                key = identity(value)
                entry = find_entry(self._entries, key)
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
                entries = replace_stored_entry(
                    self._entries,
                    key,
                    replace_entry(entry, consumed=True),
                )
                object_setattr(self, "_entries", entries)
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
            _get_call_frame: Callable[[int], Any] = ...,
            _rlock: Callable[[], threading.RLock] = ...,
            _register_at_fork: Callable[..., None] | None = ...,
            _seal_callers: frozenset[object] = ...,
            _transition_callers: frozenset[object] = ...,
            _consume_action_callers: frozenset[object] = ...,
            _finalize_actions_callers: frozenset[object] = ...,
            _consume_callers: frozenset[object] = ...,
            _transfer_callers: frozenset[object] = ...,
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
            consumed: bool | None = None,
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

        def consume_action_and_transfer(
            self,
            source: object,
            *,
            source_snapshot_sha256: str,
            source_kind: str,
            action: str,
            result: object,
            result_snapshot_sha256: str,
            result_kind: str,
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


_claim_lifecycle_v2_runtime_seal_bootstrap = _install_lifecycle_v2_runtime_seal_bootstrap_claim()
del _install_lifecycle_v2_runtime_seal_bootstrap_claim
globals().pop("_REGISTER_AT_FORK", None)
globals().pop("NamedTuple", None)
globals().pop("replace", None)
globals().pop("sys", None)


__all__ = ["LifecycleV2RuntimeSealRegistry", "RuntimeSealMetadata"]
