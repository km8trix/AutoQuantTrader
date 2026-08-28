"""Build the closed Wave 7 endpoint/resource native test profile."""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sysconfig
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve(strict=True).parents[1]
NATIVE = ROOT / "native"
HARNESS = ROOT / "tests" / "native" / "trusted_time_v2_endpoint_resources_harness.c"


class EndpointTestBuildError(RuntimeError):
    """The exact endpoint/resource test profile could not be built."""


def _fail(message: str) -> NoReturn:
    raise EndpointTestBuildError(message)


def _compiler() -> Path:
    configured = os.environ.get("CC") or sysconfig.get_config_var("CC") or "cc"
    words = shlex.split(configured)
    if not words:
        _fail("the configured C compiler is empty")
    resolved = shutil.which(words[0])
    if resolved is None:
        _fail("a C11 compiler is unavailable")
    compiler = Path(resolved).resolve(strict=True)
    metadata = compiler.stat()
    if not stat.S_ISREG(metadata.st_mode):
        _fail("the C compiler is not a regular file")
    return compiler


def build(output: Path) -> Path:
    """Build one non-installed harness at the caller-selected output path."""

    if sysconfig.get_platform() == "" or sysconfig.get_config_var("CC") is None:
        _fail("the Python build platform is unavailable")
    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        _fail("free-threaded Python is outside the admitted native profile")
    if sysconfig.get_config_var("HOST_GNU_TYPE") is None and os.name != "posix":
        _fail("the native build host is unsupported")
    if platform.system() not in {"Darwin", "Linux"}:
        _fail("only Darwin portable evidence and Linux qualification are supported")
    output = output.resolve()
    if output.exists():
        _fail("the output path must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = (
        str(_compiler()),
        "-std=c11",
        "-O2",
        "-fno-lto",
        "-fPIE",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror",
        "-pthread",
        "-DAQT_TRUSTED_TIME_V2_ENDPOINT_TESTING",
        f"-I{NATIVE}",
        str(NATIVE / "trusted_time_v2_fork_guard.c"),
        str(NATIVE / "trusted_time_graceful_stop_v2_resources.c"),
        str(NATIVE / "trusted_time_graceful_stop_v2_endpoint.c"),
        str(HARNESS),
        "-o",
        str(output),
    )
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": str(output.parent),
        },
    )
    if completed.returncode != 0:
        rendered = completed.stdout[:262_144].decode("utf-8", errors="replace")
        _fail(f"endpoint/resource test build failed:\n{rendered}")
    metadata = output.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(output, os.X_OK):
        _fail("the endpoint/resource harness output is not executable")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the closed trusted-time v2 endpoint/resource harness."
    )
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    print(build(arguments.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
