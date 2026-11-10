"""Private aliases for the statically linked bounded-process transaction.

Only the separately admitted trusted-time admission launcher and the test-only
launcher register this native builtin.  The operational runtime does not link
or publish process-spawn authority.  The launcher captures the builtin before
any target code, removes its temporary top-level import name, and executes
these exact embedded bytes in a pre-created private module.

The native transaction returns only after its child process group is killed as
needed, its direct child is reaped, and every pipe is closed.  No PID, process
object, descriptor number, or mutable capture buffer crosses into Python.
Portable POSIX process groups do not contain a descendant that deliberately
creates a new session.  Authority call sites must therefore bind an exact
content-pinned executable/argument/environment call graph that excludes such
escape, or run inside an externally admitted cgroup, job, or sandbox.  This
primitive does not claim arbitrary escaped-descendant containment.
"""

from __future__ import annotations

import sys
from types import BuiltinFunctionType, ModuleType
from typing import TYPE_CHECKING, Never, cast

__all__: tuple[()] = ()

_NATIVE_MODULE_NAME = "_autoquant_native_bounded_process"
_NATIVE_FUNCTION_NAMES = (
    "_run_bounded_process",
    "_capabilities",
    "_self_test",
)
_EXPECTED_CAPABILITIES = (
    "cpython-c-bounded-process-v1",
    "exact-immutable-input-and-result-tuples",
    "absolute-executable-no-path-search",
    "native-posix-spawn-chdir-process-group",
    "exact-stdio-pipes-and-environment",
    "bounded-stdin-stdout-stderr-deadline",
    "kill-group-and-reap-before-python-signal",
    "gil-held-no-live-process-capability",
)


class _NativeBoundedProcessLoadError(ImportError):
    """The exact native process transaction failed closed during admission."""


def _fail(message: str) -> Never:
    raise _NativeBoundedProcessLoadError(message)


def _validate_native_api(
    native_module: ModuleType,
) -> tuple[BuiltinFunctionType, BuiltinFunctionType, BuiltinFunctionType]:
    if native_module.__name__ != _NATIVE_MODULE_NAME:
        _fail("native bounded-process module name is invalid")
    if frozenset(vars(native_module)) != frozenset(
        ("__doc__", "__name__", *_NATIVE_FUNCTION_NAMES)
    ):
        _fail("native bounded-process module exports are invalid")
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
            _fail("native bounded-process API function is invalid")
    validated = cast(
        tuple[BuiltinFunctionType, BuiltinFunctionType, BuiltinFunctionType],
        native_functions,
    )
    if validated[1]() != _EXPECTED_CAPABILITIES or validated[2]() is not None:
        _fail("native bounded-process capability self-test failed")
    return validated


if TYPE_CHECKING:
    _AQT_PRELOADED_NATIVE_PROCESS_MODULE: object

try:
    _preloaded_candidate: object = _AQT_PRELOADED_NATIVE_PROCESS_MODULE
except NameError:
    _fail("native bounded-process wrapper requires the admitted launcher")

if (
    sys.implementation.name != "cpython"
    or sys.version_info[:2] not in ((3, 12), (3, 13))
    or sys.platform not in ("darwin", "linux")
    or type(_preloaded_candidate) is not ModuleType
    or _NATIVE_MODULE_NAME in sys.modules
):
    _fail("native bounded-process launcher handoff is invalid")

_native_module = _preloaded_candidate
_native_run_bounded_process, _native_capabilities, _native_self_test = _validate_native_api(
    _native_module
)
del _preloaded_candidate

_BoundedProcessResult = tuple[tuple[str, ...], int, bytes, bytes]

if TYPE_CHECKING:

    def _run_bounded_process(
        argv: tuple[str, ...],
        cwd: str,
        environment: tuple[tuple[str, str], ...],
        stdin: bytes,
        stdout_cap: int,
        stderr_cap: int,
        timeout_ns: int,
    ) -> _BoundedProcessResult: ...

    def _native_bounded_process_capabilities() -> tuple[str, ...]: ...

    def _native_bounded_process_self_test() -> None: ...

else:
    _run_bounded_process = _native_run_bounded_process
    _native_bounded_process_capabilities = _native_capabilities
    _native_bounded_process_self_test = _native_self_test

if _NATIVE_MODULE_NAME in sys.modules:
    _fail("native bounded-process module was registered during wrapper publication")
