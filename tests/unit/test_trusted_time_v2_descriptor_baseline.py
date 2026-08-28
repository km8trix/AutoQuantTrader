from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
SOURCE = NATIVE / "trusted_time_v2_descriptor_baseline.c"
HARNESS = ROOT / "tests/native/trusted_time_v2_descriptor_baseline_harness.c"


def _compiler() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the descriptor-baseline gate")
    return compiler


def test_descriptor_baseline_closes_ambient_fds_and_rejects_socket_stdio(
    tmp_path: Path,
) -> None:
    output = tmp_path / "descriptor-baseline"
    subprocess.run(
        [
            _compiler(),
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-Wshadow",
            "-Wpedantic",
            "-Werror",
            f"-I{NATIVE}",
            str(SOURCE),
            str(HARNESS),
            "-o",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for mode in ("standard", "ambient", "socket-stdio"):
        result = subprocess.run(
            [output, mode],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
        assert result.returncode == 0, (mode, result.stdout)
