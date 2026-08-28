"""Inert entry for the unactivated lifecycle-v2 recovery candidate."""

from __future__ import annotations

import sys

_EXPECTED_PATH = [
    "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python-runtime",
    "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python",
]
_FORBIDDEN_LOADED_MODULES = (
    "_ctypes",
    "_posixsubprocess",
    "_socket",
    "asyncio",
    "concurrent",
    "ctypes",
    "http",
    "importlib",
    "multiprocessing",
    "pathlib",
    "pkgutil",
    "runpy",
    "shutil",
    "socket",
    "subprocess",
    "urllib",
)


def run() -> None:
    """Refuse use until a later milestone supplies operational composition."""

    if sys.path != _EXPECTED_PATH:
        raise RuntimeError("the recovery candidate import path is not exact")
    if any(
        name == forbidden or name.startswith(f"{forbidden}.")
        for name in sys.modules
        for forbidden in _FORBIDDEN_LOADED_MODULES
    ):
        raise RuntimeError("the recovery candidate loaded a forbidden module")
    print("AQT_WAVE7_INERT_RECOVERY_ENTRY_REACHED", flush=True)
    raise RuntimeError("the lifecycle-v2 recovery candidate is unactivated")
