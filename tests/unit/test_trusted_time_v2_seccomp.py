from __future__ import annotations

import platform
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
HARNESS = ROOT / "tests/native/trusted_time_v2_seccomp_harness.c"
SECCOMP = NATIVE / "trusted_time_v2_seccomp.c"

PROFILES = {
    "host": "AQT_TRUSTED_TIME_V2_HOST_PROFILE",
    "supervisor": "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE",
    "recovery": "AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE",
    "provisioner": "AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE",
}


def _compiler() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the native seccomp gate")
    return compiler


@pytest.fixture(scope="module")
def seccomp_harnesses(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    if platform.system() != "Linux":
        pytest.skip("seccomp is qualified only on Linux")
    build = tmp_path_factory.mktemp("trusted-time-v2-seccomp")
    outputs: dict[str, Path] = {}
    for role, macro in PROFILES.items():
        output = build / role
        subprocess.run(
            [
                _compiler(),
                "-std=c11",
                "-O2",
                "-fPIE",
                "-fvisibility=hidden",
                "-fstack-protector-strong",
                "-Wall",
                "-Wextra",
                "-Wconversion",
                "-Wshadow",
                "-Wpedantic",
                "-Werror",
                f"-D{macro}=1",
                f"-I{NATIVE}",
                str(SECCOMP),
                str(HARNESS),
                "-pthread",
                "-o",
                str(output),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs[role] = output
    return outputs


def _run(harness: Path, mode: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [harness, mode],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=10,
    )


def test_default_deny_blocks_unknown_dangerous_and_process_surfaces(
    seccomp_harnesses: dict[str, Path],
) -> None:
    for harness in seccomp_harnesses.values():
        for mode in ("allowed", "unknown", "dangerous", "process", "arguments"):
            result = _run(harness, mode)
            assert result.returncode == 0, (harness.name, mode, result.stdout)


def test_socket_surface_is_role_asymmetric_and_argument_filtered(
    seccomp_harnesses: dict[str, Path],
) -> None:
    for harness in seccomp_harnesses.values():
        result = _run(harness, "socket")
        assert result.returncode == 0, (harness.name, result.stdout)


def test_provisioner_child_and_post_child_filters_remove_ambient_authority(
    seccomp_harnesses: dict[str, Path],
) -> None:
    for mode in ("child-filter", "post-child"):
        result = _run(seccomp_harnesses["provisioner"], mode)
        assert result.returncode == 0, (mode, result.stdout)


def test_tsync_applies_default_deny_to_preexisting_sibling_thread(
    seccomp_harnesses: dict[str, Path],
) -> None:
    for harness in seccomp_harnesses.values():
        result = _run(harness, "tsync")
        assert result.returncode == 0, (harness.name, result.stdout)


def test_x86_64_x32_namespace_is_killed(
    seccomp_harnesses: dict[str, Path],
) -> None:
    for harness in seccomp_harnesses.values():
        result = _run(harness, "x32")
        if platform.machine() == "x86_64":
            assert result.returncode == -signal.SIGSYS, (harness.name, result.stdout)
        else:
            assert result.returncode == 77
