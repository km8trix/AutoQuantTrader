"""Private Python names for the statically linked native authority primitives.

This module is not a dynamic-extension loader.  The admitted trusted-time
launcher registers the top-level native builtin before Python initialization,
captures it in C, removes its temporary import name, and executes these exact
embedded source bytes in a pre-created module.  Ordinary Python imports cannot
bootstrap the native authority.

The production activation boundary is the reviewed root-owned, read-only
trusted-time runtime image.  Developer wheels include a byte-identical launcher
for build and test evidence, but a user-owned prefix is never authoritative.
The launcher and its complete dynamic-loader, libpython, stdlib, installed
RECORD, and native-artifact closure are admitted by external image policy before
the process is entered.

The exact graph forbids ``ctypes``, other dynamic-loader aliases, raw
``/proc/self/fd`` enumeration, and arbitrary same-process native code.  A Linux
``kcmp`` open-file-description anchor is therefore defense in depth rather than
part of this boundary: no descriptor number is ever published to an attacker.

No live descriptor number is exposed.  Fresh owners cross into Python only as
the direct result of exact C builtins, so no Python helper frame can retain a
new owner across a RETURN-to-STORE interruption.
"""

from __future__ import annotations

import sys
from types import BuiltinFunctionType, ModuleType
from typing import TYPE_CHECKING, Never, cast, final

__all__: tuple[()] = ()

_NATIVE_MODULE_NAME = "_autoquant_native_owned_file_descriptor"
_NATIVE_FUNCTION_NAMES = (
    "_open_root_directory",
    "_open_child_directory",
    "_open_child_regular",
    "_create_child_regular_exclusive",
    "_fstat",
    "_statat",
    "_read_snapshot",
    "_list_snapshot",
    "_flock",
    "_fsync",
    "_write_all",
    "_ftruncate",
    "_fchmod_0600",
    "_acquire_trusted_time_launch_lock",
    "_validate_trusted_time_launch_lock",
    "_capabilities",
    "_self_test",
)
_EXPECTED_CAPABILITIES = (
    "cpython-c-extension-owned-fd-v3",
    "no-python-visible-descriptor",
    "atomic-owner-cell",
    "operation-specific-open-profiles",
    "o-cloexec-and-nofollow-mandatory",
    "native-owner-authority-syscalls",
    "bounded-offset-zero-read-write-snapshots",
    "bounded-sorted-directory-snapshot",
    "nonblocking-flock-and-fsync",
    "opaque-trusted-time-launch-lock-lease",
    "two-phase-current-path-launch-lock-validation",
    "pthread-atfork-child-sweep",
    (
        "darwin-fdguard-generation-close"
        if sys.platform == "darwin"
        else "linux-close-once-no-retry"
    ),
)


class _NativeOwnedFileDescriptorLoadError(ImportError):
    """The exact native ownership primitive failed closed during admission."""


def _fail(message: str) -> Never:
    raise _NativeOwnedFileDescriptorLoadError(message)


def _validate_native_api(
    native_module: ModuleType,
) -> tuple[type[object], type[object], tuple[BuiltinFunctionType, ...]]:
    if native_module.__name__ != _NATIVE_MODULE_NAME:
        _fail("native owned-file-descriptor module name is invalid")
    expected_module_attributes = frozenset(
        (
            "__doc__",
            "__name__",
            "_OwnedFileDescriptor",
            "_TrustedTimeLaunchLockLease",
            *_NATIVE_FUNCTION_NAMES,
        )
    )
    if frozenset(vars(native_module)) != expected_module_attributes:
        _fail("native owned-file-descriptor module exports are invalid")

    owner_type = getattr(native_module, "_OwnedFileDescriptor", None)
    if type(owner_type) is not type:
        _fail("native owned-file-descriptor API type is invalid")
    if (
        owner_type.__module__ != _NATIVE_MODULE_NAME
        or owner_type.__name__ != "_OwnedFileDescriptor"
        or owner_type.__bases__ != (object,)
        or owner_type.__dict__.get("__dict__") is not None
        or owner_type.__dict__.get("__weakref__") is not None
        or frozenset(owner_type.__dict__)
        != frozenset(("__doc__", "__reduce__", "__reduce_ex__", "__repr__", "close", "closed"))
        or hasattr(owner_type, "fileno")
        or hasattr(owner_type, "detach")
    ):
        _fail("native owned-file-descriptor exact type is invalid")

    launch_lock_lease_type = getattr(native_module, "_TrustedTimeLaunchLockLease", None)
    if type(launch_lock_lease_type) is not type:
        _fail("native trusted-time launch-lock lease API type is invalid")
    if (
        launch_lock_lease_type.__module__ != _NATIVE_MODULE_NAME
        or launch_lock_lease_type.__name__ != "_TrustedTimeLaunchLockLease"
        or launch_lock_lease_type.__bases__ != (object,)
        or launch_lock_lease_type.__dict__.get("__dict__") is not None
        or launch_lock_lease_type.__dict__.get("__weakref__") is not None
        or frozenset(launch_lock_lease_type.__dict__)
        != frozenset(("__doc__", "__reduce__", "__reduce_ex__", "__repr__", "close", "closed"))
        or hasattr(launch_lock_lease_type, "fileno")
        or hasattr(launch_lock_lease_type, "detach")
    ):
        _fail("native trusted-time launch-lock lease exact type is invalid")

    native_functions = tuple(
        getattr(native_module, function_name, None) for function_name in _NATIVE_FUNCTION_NAMES
    )
    for function_name, native_function in zip(
        _NATIVE_FUNCTION_NAMES,
        native_functions,
        strict=True,
    ):
        if (
            type(native_function) is not BuiltinFunctionType
            or native_function.__name__ != function_name
            or native_function.__module__ != _NATIVE_MODULE_NAME
            or native_function.__self__ is not native_module
        ):
            _fail("native owned-file-descriptor API function is invalid")
    validated_functions = cast(tuple[BuiltinFunctionType, ...], native_functions)
    if validated_functions[-2]() != _EXPECTED_CAPABILITIES or validated_functions[-1]() is not None:
        _fail("native owned-file-descriptor capability self-test failed")
    return (
        cast(type[object], owner_type),
        cast(type[object], launch_lock_lease_type),
        validated_functions,
    )


if TYPE_CHECKING:
    _AQT_PRELOADED_NATIVE_MODULE: object

try:
    _preloaded_candidate: object = _AQT_PRELOADED_NATIVE_MODULE
except NameError:
    _fail("native owned-file-descriptor wrapper requires the admitted launcher")

if (
    sys.implementation.name != "cpython"
    or sys.version_info[:2] not in ((3, 12), (3, 13))
    or sys.platform not in ("darwin", "linux")
    or type(_preloaded_candidate) is not ModuleType
    or _NATIVE_MODULE_NAME in sys.modules
):
    _fail("native owned-file-descriptor launcher handoff is invalid")

_native_module = _preloaded_candidate
(
    _native_owner_type,
    _native_launch_lock_lease_type,
    _native_functions,
) = _validate_native_api(_native_module)
del _preloaded_candidate

(
    _native_open_root_directory,
    _native_open_child_directory,
    _native_open_child_regular,
    _native_create_child_regular_exclusive,
    _native_fstat,
    _native_statat,
    _native_read_snapshot,
    _native_list_snapshot,
    _native_flock,
    _native_fsync,
    _native_write_all,
    _native_ftruncate,
    _native_fchmod_0600,
    _native_acquire_trusted_time_launch_lock,
    _native_validate_trusted_time_launch_lock,
    _native_capabilities,
    _native_self_test,
) = _native_functions

_Stat9 = tuple[int, int, int, int, int, int, int, int, int]
_ReadSnapshot = tuple[bytes, _Stat9, _Stat9]
_ListSnapshot = tuple[tuple[str, ...], _Stat9, _Stat9]

if TYPE_CHECKING:

    @final
    class _OwnedFileDescriptor:
        @property
        def closed(self) -> bool: ...

        def close(self) -> None: ...

    @final
    class _TrustedTimeLaunchLockLease:
        @property
        def closed(self) -> bool: ...

        def close(self) -> None: ...

    def _open_root_directory() -> _OwnedFileDescriptor: ...

    def _open_child_directory(
        directory: _OwnedFileDescriptor,
        component: str | bytes,
    ) -> _OwnedFileDescriptor: ...

    def _open_child_regular(
        directory: _OwnedFileDescriptor,
        component: str | bytes,
    ) -> _OwnedFileDescriptor: ...

    def _create_child_regular_exclusive(
        directory: _OwnedFileDescriptor,
        component: str | bytes,
    ) -> _OwnedFileDescriptor: ...

    def _fstat(owner: _OwnedFileDescriptor) -> _Stat9: ...

    def _statat(directory: _OwnedFileDescriptor, component: str | bytes) -> _Stat9: ...

    def _read_snapshot(owner: _OwnedFileDescriptor, maximum_bytes: int) -> _ReadSnapshot: ...

    def _list_snapshot(directory: _OwnedFileDescriptor) -> _ListSnapshot: ...

    def _flock(owner: _OwnedFileDescriptor, operation: int) -> None: ...

    def _fsync(owner: _OwnedFileDescriptor) -> None: ...

    def _write_all(owner: _OwnedFileDescriptor, payload: bytes) -> None: ...

    def _ftruncate(owner: _OwnedFileDescriptor, length: int) -> None: ...

    def _fchmod_0600(owner: _OwnedFileDescriptor) -> None: ...

    def _acquire_trusted_time_launch_lock(
        ignored_root: str,
        /,
    ) -> _TrustedTimeLaunchLockLease: ...

    def _validate_trusted_time_launch_lock(
        lease: _TrustedTimeLaunchLockLease,
        /,
    ) -> None: ...

    def _native_owned_file_descriptor_capabilities() -> tuple[str, ...]: ...

    def _native_owned_file_descriptor_self_test() -> None: ...

else:
    _OwnedFileDescriptor = _native_owner_type
    _TrustedTimeLaunchLockLease = _native_launch_lock_lease_type
    _open_root_directory = _native_open_root_directory
    _open_child_directory = _native_open_child_directory
    _open_child_regular = _native_open_child_regular
    _create_child_regular_exclusive = _native_create_child_regular_exclusive
    _fstat = _native_fstat
    _statat = _native_statat
    _read_snapshot = _native_read_snapshot
    _list_snapshot = _native_list_snapshot
    _flock = _native_flock
    _fsync = _native_fsync
    _write_all = _native_write_all
    _ftruncate = _native_ftruncate
    _fchmod_0600 = _native_fchmod_0600
    _acquire_trusted_time_launch_lock = _native_acquire_trusted_time_launch_lock
    _validate_trusted_time_launch_lock = _native_validate_trusted_time_launch_lock
    _native_owned_file_descriptor_capabilities = _native_capabilities
    _native_owned_file_descriptor_self_test = _native_self_test

if _NATIVE_MODULE_NAME in sys.modules:
    _fail("native owned-file-descriptor module was registered during wrapper publication")
