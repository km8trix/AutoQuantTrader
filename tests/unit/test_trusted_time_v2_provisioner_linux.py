from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
FIXTURES = ROOT / "tests/fixtures/native/trusted-time-v2"
MONOCYPHER = ROOT / "third_party/monocypher/4.0.3/src"
OPTIONAL = MONOCYPHER / "optional"


def _compiler() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the Linux provisioner gate")
    return compiler


def _definition(name: str, value: Path | str) -> str:
    payload = str(value)
    assert '"' not in payload and "\\" not in payload
    return f'-D{name}="{payload}"'


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux seccomp gate")
def test_real_provisioner_child_path_is_positive_and_single_use(tmp_path: Path) -> None:
    child = tmp_path / "fake-systemd-creds"
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
            str(FIXTURES / "provisioner_positive_child.c"),
            "-o",
            str(child),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    child.chmod(0o755)
    child_sha256 = hashlib.sha256(child.read_bytes()).hexdigest()

    blob_prefix = tmp_path / "encrypted-host-g"
    blob = tmp_path / "encrypted-host-g00000001.cred"
    blob.write_bytes(b"fixed encrypted credential fixture\n")
    blob.chmod(0o600)
    blob_metadata = blob.stat()
    assert blob_metadata.st_uid == os.geteuid()
    assert blob_metadata.st_gid == os.getegid()
    target = tmp_path / "host-secrets"
    target.mkdir(mode=0o700)
    output = tmp_path / "autoquant-trusted-time-graceful-stop-v2-host-provision"
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
            "-DAQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE=1",
            "-DAQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD=1",
            _definition("AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256", child_sha256),
            _definition("AQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH", child),
            _definition("AQT_TRUSTED_TIME_V2_TEST_BLOB_PREFIX", blob_prefix),
            _definition("AQT_TRUSTED_TIME_V2_TEST_TARGET_DIRECTORY", target),
            f"-I{NATIVE}",
            f"-I{MONOCYPHER}",
            f"-I{OPTIONAL}",
            str(NATIVE / "trusted_time_v2_provisioner.c"),
            str(NATIVE / "trusted_time_v2_descriptor_baseline.c"),
            str(NATIVE / "trusted_time_v2_seccomp.c"),
            str(MONOCYPHER / "monocypher.c"),
            str(OPTIONAL / "monocypher-ed25519.c"),
            str(FIXTURES / "provisioner_positive_stubs.c"),
            "-o",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    output.chmod(0o755)

    first = subprocess.run(
        [output],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert first.returncode == 0, first.stdout
    secret = target / "host-ed25519.raw"
    assert secret.read_bytes() == bytes(range(32))
    assert secret.stat().st_mode & 0o777 == 0o400

    second = subprocess.run(
        [output],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert second.returncode == 191, second.stdout
    assert secret.read_bytes() == bytes(range(32))
