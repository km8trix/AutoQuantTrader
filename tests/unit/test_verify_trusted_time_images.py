from __future__ import annotations

import ctypes
import dis
import gc
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from packages.adapters.trusted_time._bounded_process import _run_bounded_process
from scripts import verify_trusted_time_images as image_verifier
from scripts.verify_trusted_time_images import (
    AUTHORITY_SHA256,
    CONFIG_SHA256,
    DATABASE_CA_SHA256,
    EXPECTED_CATALOG_RELATIONS,
    EXPECTED_SCHEMA_REVISION,
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    ROOT,
    SOURCE_IMAGE,
    SUPERVISOR_SCHEMA_CONTRACT_COMMAND,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
    _build_suspend_aware_monotonic_clock,
    _current_boot_session_id,
    _current_clean_git_revision,
    _DarwinMachTimebaseInfo,
    _decode_admission_payload,
    _head_reviewed_input_payload,
    _head_reviewed_operator_authority_object,
    _minimal_git_environment,
    _probe_runtime_topology,
    _require_head_reviewed_inputs,
    _require_isolated_cli_source_runtime,
    _require_repository_first_party_sources,
    _reviewed_input_paths,
    _run_read_only,
    _sealed_head_build_context,
    _validate_trusted_time_dockerfile_frontend,
    _validate_trusted_time_dockerignore_contract,
    build_and_verify_images,
    build_trusted_time_images,
    build_verify_and_write_image_admission,
    load_image_admission_artifact,
    load_image_admission_provenance_artifact,
    resolve_image_id,
    reviewed_input_bindings,
    validate_ca_trust_store,
    validate_chronyc_version,
    validate_chronyd_version,
    validate_config_hashes,
    validate_database_ca_metadata,
    validate_operational_schema_contract,
    validate_secretless_supervisor,
    validate_source_inspection,
    validate_static_chronyc,
    validate_supervisor_inspection,
    verify_and_write_existing_image_admission,
    write_image_admission_artifact,
)

SOURCE_ID = "sha256:" + "1" * 64
SUPERVISOR_ID = "sha256:" + "2" * 64
SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256 = "d" * 64
BOOT_SESSION_ID = "linux:11111111-2222-3333-4444-555555555555"
NEXT_BOOT_SESSION_ID = "linux:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DARWIN_BOOT_SESSION_ID = "darwin:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OPERATOR_AUTHORITY_RELATIVE_PATH = Path(
    "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
)
NATIVE_OPERATOR_GIT_ENVIRONMENT = (
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/bin:/bin"),
    ("TMPDIR", "/tmp"),
)
NATIVE_BUILD_CONTEXT_RELATIVE_PATHS = (
    "build_support/native_build_constraints.txt",
    "build_support/native_image_manifest.py",
    "build_support/native_owned_file_descriptor_hook.py",
    "native/bounded_process.c",
    "native/owned_file_descriptor.c",
    "native/trusted_time_python_launcher.c",
)


def _immutable_docker_result(
    stdout: str = "",
    *,
    returncode: int = 0,
    stderr: str = "",
) -> image_verifier._ImmutableTextSubprocessResult:
    return (("docker",), returncode, stdout, stderr)


def _bytes_result(
    argv: tuple[str, ...],
    returncode: int,
    stdout: bytes,
    stderr: bytes,
) -> image_verifier.BoundedSubprocessResult:
    return (argv, returncode, stdout, stderr)


def _operator_authority_native_result(
    argv: tuple[str, ...],
    *,
    call_number: int,
    revision: str,
    object_id: str,
    payload: bytes,
) -> tuple[tuple[str, ...], int, bytes, bytes]:
    if call_number == 1:
        return (argv, 0, revision.encode("ascii") + b"\n", b"")
    if call_number == 2:
        return (
            argv,
            0,
            (
                b"100644 blob "
                + object_id.encode("ascii")
                + b"\t"
                + OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix().encode("ascii")
                + b"\0"
            ),
            b"",
        )
    if call_number == 3:
        return (
            argv,
            0,
            (
                object_id.encode("ascii")
                + b" blob "
                + str(len(payload)).encode("ascii")
                + b"\n"
                + payload
                + b"\n"
            ),
            b"",
        )
    raise AssertionError("unexpected native Git transaction")


def _socket_volume_projection_json(
    *,
    volume_name: str,
    token: str,
) -> str:
    return (
        json.dumps(
            {
                "driver": "local",
                "label_count": 1,
                "label_token": token,
                "name": volume_name,
                "option_count": 3,
                "option_device": "tmpfs",
                "option_o": ("rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0750"),
                "option_type": "tmpfs",
                "scope": "local",
                "status": None,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _source_probe_projection_json(
    *,
    image_id: str,
    volume_name: str,
    token: str,
) -> str:
    return (
        json.dumps(
            {
                "bind_count": 0,
                "cap_add_count": 0,
                "cap_drop_0": "ALL",
                "cap_drop_count": 1,
                "config_user": "10001:10001",
                "container_label_count": 1,
                "container_label_token": token,
                "device_count": 0,
                "device_request_count": 0,
                "host_mount_count": 1,
                "host_mount_driver_config": None,
                "host_mount_no_copy": True,
                "host_mount_read_only": False,
                "host_mount_source": volume_name,
                "host_mount_target": "/run/chrony",
                "host_mount_type": "volume",
                "image": image_id,
                "mount_count": 1,
                "mount_destination": "/run/chrony",
                "mount_driver": "local",
                "mount_mode": "z",
                "mount_name": volume_name,
                "mount_propagation": "",
                "mount_rw": True,
                "mount_type": "volume",
                "network_mode": "none",
                "pids_limit": 32,
                "port_binding_count": 0,
                "privileged": False,
                "readonly_rootfs": True,
                "running": True,
                "security_opt_0": "no-new-privileges",
                "security_opt_count": 1,
                "tmpfs_count": 2,
                "tmpfs_tmp": ("rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"),
                "tmpfs_var_lib_chrony": (
                    "rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _replace_tuple_slot(
    value: tuple[object, ...],
    index: int,
    replacement: object,
) -> tuple[object, ...]:
    return (*value[:index], replacement, *value[index + 1 :])


@pytest.fixture(autouse=True)
def _stable_boot_session_identity() -> Iterator[None]:
    with patch(
        "scripts.verify_trusted_time_images._current_boot_session_id",
        return_value=BOOT_SESSION_ID,
    ):
        yield


@pytest.fixture
def native_git_root() -> Iterator[Path]:
    git_metadata = os.lstat("/usr/bin/git")
    if (
        not stat.S_ISREG(git_metadata.st_mode)
        or git_metadata.st_nlink != 1
        or os.path.realpath("/usr/bin/git") != "/usr/bin/git"
    ):
        pytest.skip("this platform's /usr/bin/git is not admitted by the native test profile")
    with tempfile.TemporaryDirectory(prefix=".native-operator-git-", dir=ROOT) as directory:
        root = Path(directory).resolve(strict=True)
        root.chmod(0o700)
        yield root


def test_linux_image_admission_clock_uses_exact_suspend_aware_clock_id() -> None:
    calls: list[int] = []

    def clock_gettime_ns(clock_id: int) -> int:
        calls.append(clock_id)
        return 41 + len(calls)

    clock = _build_suspend_aware_monotonic_clock(
        platform_name="linux",
        clock_gettime_ns=clock_gettime_ns,
        clock_boottime=7,
        darwin_library_loader=lambda _: (_ for _ in ()).throw(AssertionError),
    )

    assert clock() == 42
    assert clock() == 43
    assert calls == [7, 7]


def test_darwin_image_admission_clock_captures_validated_timebase_once() -> None:
    calls: list[str] = []

    def continuous_time() -> int:
        calls.append("continuous")
        return 10

    def timebase_info(pointer: Any) -> int:
        calls.append("timebase")
        timebase = ctypes.cast(
            pointer,
            ctypes.POINTER(_DarwinMachTimebaseInfo),
        ).contents
        timebase.numer = 3
        timebase.denom = 2
        return 0

    clock = _build_suspend_aware_monotonic_clock(
        platform_name="darwin",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=lambda _: SimpleNamespace(
            mach_continuous_time=continuous_time,
            mach_timebase_info=timebase_info,
        ),
    )

    assert clock() == 15
    assert clock() == 15
    assert calls == ["timebase", "continuous", "continuous"]


@pytest.mark.parametrize(("numerator", "denominator"), [(0, 1), (1, 0)])
def test_darwin_image_admission_clock_rejects_invalid_timebase(
    numerator: int,
    denominator: int,
) -> None:
    def timebase_info(pointer: Any) -> int:
        timebase = ctypes.cast(
            pointer,
            ctypes.POINTER(_DarwinMachTimebaseInfo),
        ).contents
        timebase.numer = numerator
        timebase.denom = denominator
        return 0

    clock = _build_suspend_aware_monotonic_clock(
        platform_name="darwin",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=lambda _: SimpleNamespace(
            mach_continuous_time=lambda: 1,
            mach_timebase_info=timebase_info,
        ),
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="suspend-aware"):
        clock()


def test_unsupported_image_admission_clock_fails_closed() -> None:
    clock = _build_suspend_aware_monotonic_clock(
        platform_name="unsupported",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=None,
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="suspend-aware"):
        clock()


def test_cli_runtime_attestation_accepts_isolated_source_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_images.py"
    runtime_prefix = tmp_path / "uv-isolated"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)
    runtime_path = [os.fspath(base_prefix / "lib")]

    with (
        patch(
            "scripts.verify_trusted_time_images.sys.flags",
            SimpleNamespace(isolated=1, dont_write_bytecode=1),
        ),
        patch("scripts.verify_trusted_time_images.sys.pycache_prefix", "/dev/null"),
        patch("scripts.verify_trusted_time_images.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_images.sys.base_prefix", os.fspath(base_prefix)),
        patch("scripts.verify_trusted_time_images.sys.path", runtime_path),
    ):
        observed_root = _require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_images.py"),
            module_file=os.fspath(source),
        )

        assert observed_root == root
        assert runtime_path[0] == os.fspath(root)


@pytest.mark.parametrize(
    ("isolated", "dont_write_bytecode", "pycache_prefix"),
    [
        (0, 1, "/dev/null"),
        (1, 0, "/dev/null"),
        (1, 1, None),
        (1, 1, "repository-cache"),
    ],
)
def test_cli_runtime_attestation_rejects_unsafe_interpreter_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated: int,
    dont_write_bytecode: int,
    pycache_prefix: str | None,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_images.py"
    runtime_prefix = tmp_path / "uv-isolated"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)

    with (
        patch(
            "scripts.verify_trusted_time_images.sys.flags",
            SimpleNamespace(
                isolated=isolated,
                dont_write_bytecode=dont_write_bytecode,
            ),
        ),
        patch("scripts.verify_trusted_time_images.sys.pycache_prefix", pycache_prefix),
        patch("scripts.verify_trusted_time_images.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_images.sys.base_prefix", os.fspath(base_prefix)),
        patch("scripts.verify_trusted_time_images.sys.path", [os.fspath(base_prefix / "lib")]),
        pytest.raises(RuntimeError, match="runtime attestation failed"),
    ):
        _require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_images.py"),
            module_file=os.fspath(source),
        )


def test_cli_runtime_attestation_rejects_repository_virtual_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_images.py"
    runtime_prefix = root / ".venv"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)

    with (
        patch(
            "scripts.verify_trusted_time_images.sys.flags",
            SimpleNamespace(isolated=1, dont_write_bytecode=1),
        ),
        patch("scripts.verify_trusted_time_images.sys.pycache_prefix", "/dev/null"),
        patch("scripts.verify_trusted_time_images.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_images.sys.base_prefix", os.fspath(base_prefix)),
        patch("scripts.verify_trusted_time_images.sys.path", [os.fspath(runtime_prefix / "lib")]),
        pytest.raises(RuntimeError, match="runtime attestation failed"),
    ):
        _require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_images.py"),
            module_file=os.fspath(source),
        )


def test_verifier_first_party_attestation_rejects_bytecode_origin(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    bytecode = root / "scripts" / "__pycache__" / "bounded_subprocess.cpython-312.pyc"
    bytecode.parent.mkdir(parents=True)
    bytecode.write_bytes(b"poisoned")
    isolated_sys = SimpleNamespace(
        modules={"scripts.bounded_subprocess": SimpleNamespace(__file__=os.fspath(bytecode))}
    )

    with (
        patch("scripts.verify_trusted_time_images.sys", isolated_sys),
        pytest.raises(RuntimeError, match="first-party source attestation failed"),
    ):
        _require_repository_first_party_sources(root)


def test_linux_boot_session_identity_is_stable_and_canonical(tmp_path: Path) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_bytes(b"11111111-2222-3333-4444-555555555555\n")

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            boot_id_path,
        ),
        patch(
            "scripts.verify_trusted_time_images._open_owned_file",
            side_effect=AssertionError("legacy descriptor owner reached"),
        ) as legacy_open,
        patch(
            "scripts.verify_trusted_time_images.os.read",
            side_effect=AssertionError("Python raw descriptor read reached"),
        ) as raw_read,
        patch(
            "scripts.verify_trusted_time_images.os.fstat",
            side_effect=AssertionError("Python raw descriptor stat reached"),
        ) as raw_fstat,
    ):
        assert _current_boot_session_id() == BOOT_SESSION_ID
        assert _current_boot_session_id() == BOOT_SESSION_ID

    legacy_open.assert_not_called()
    raw_read.assert_not_called()
    raw_fstat.assert_not_called()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs boot identity contract")
def test_linux_boot_session_identity_reads_real_procfs_through_native_owner() -> None:
    with (
        patch(
            "scripts.verify_trusted_time_images._open_owned_file",
            side_effect=AssertionError("legacy descriptor owner reached"),
        ) as legacy_open,
        patch(
            "scripts.verify_trusted_time_images.os.read",
            side_effect=AssertionError("Python raw descriptor read reached"),
        ) as raw_read,
        patch(
            "scripts.verify_trusted_time_images.os.fstat",
            side_effect=AssertionError("Python raw descriptor stat reached"),
        ) as raw_fstat,
    ):
        observed = image_verifier._linux_boot_session_id()

    assert image_verifier._BOOT_SESSION_ID_PATTERN.fullmatch(observed) is not None
    assert observed.startswith("linux:")
    legacy_open.assert_not_called()
    raw_read.assert_not_called()
    raw_fstat.assert_not_called()


@pytest.mark.parametrize(
    "invalid_path",
    (
        Path("boot_id"),
        Path("/tmp/boot-id-parent/../boot_id"),
    ),
)
def test_linux_boot_session_identity_rejects_noncanonical_path_without_opening_root(
    invalid_path: Path,
) -> None:
    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch("scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH", invalid_path),
        patch(
            "scripts.verify_trusted_time_images._native_open_root_directory",
            side_effect=AssertionError("invalid boot ID path reached native open"),
        ) as native_open,
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()

    native_open.assert_not_called()


def test_linux_boot_session_identity_rejects_symlinked_directory_component(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "boot_id").write_bytes(b"11111111-2222-3333-4444-555555555555\n")
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            linked / "boot_id",
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()


def test_linux_boot_session_identity_rejects_native_read_metadata_drift(
    tmp_path: Path,
) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_bytes(b"11111111-2222-3333-4444-555555555555\n")
    real_read_snapshot = cast(Any, image_verifier)._native_read_snapshot

    def drifting_read_snapshot(owner: Any, maximum_bytes: int) -> tuple[object, ...]:
        encoded, before, after = real_read_snapshot(owner, maximum_bytes)
        drifted = list(after)
        drifted[8] += 1
        return encoded, before, tuple(drifted)

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            boot_id_path,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_read_snapshot",
            side_effect=drifting_read_snapshot,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()


@pytest.mark.parametrize(
    "failure",
    (
        OSError("boot ID native read failed"),
        RuntimeError("native descriptor module process is invalid"),
        KeyboardInterrupt("boot ID native read interrupted"),
        SystemExit(73),
    ),
)
def test_linux_boot_session_identity_closes_native_owners_and_preserves_async_failure(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_bytes(b"11111111-2222-3333-4444-555555555555\n")
    owners: list[Any] = []
    real_open_root = cast(Any, image_verifier)._native_open_root_directory
    real_open_directory = cast(Any, image_verifier)._native_open_child_directory
    real_open_regular = cast(Any, image_verifier)._native_open_child_regular

    def observed_open_root() -> Any:
        owner = real_open_root()
        owners.append(owner)
        return owner

    def observed_open_directory(directory: Any, component: str) -> Any:
        owner = real_open_directory(directory, component)
        owners.append(owner)
        return owner

    def observed_open_regular(directory: Any, component: str) -> Any:
        owner = real_open_regular(directory, component)
        owners.append(owner)
        return owner

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            boot_id_path,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_root_directory",
            side_effect=observed_open_root,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_child_directory",
            side_effect=observed_open_directory,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_child_regular",
            side_effect=observed_open_regular,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_read_snapshot",
            side_effect=failure,
        ),
    ):
        if isinstance(failure, Exception):
            with pytest.raises(
                TrustedTimeImageVerificationError,
                match="identity is unavailable",
            ):
                _current_boot_session_id()
        else:
            with pytest.raises(type(failure)) as captured:
                _current_boot_session_id()
            assert captured.value is failure

    assert owners
    assert all(owner.closed for owner in owners)


def test_linux_boot_session_identity_preserves_async_failure_during_native_cleanup(
    tmp_path: Path,
) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_bytes(b"11111111-2222-3333-4444-555555555555\n")
    owners: list[Any] = []
    interruption = KeyboardInterrupt("boot ID native cleanup interrupted")
    real_cleanup = image_verifier._cleanup_native_owned_descriptors
    real_open_root = cast(Any, image_verifier)._native_open_root_directory
    real_open_directory = cast(Any, image_verifier)._native_open_child_directory
    real_open_regular = cast(Any, image_verifier)._native_open_child_regular
    interrupted = False

    def observed_open_root() -> Any:
        owner = real_open_root()
        owners.append(owner)
        return owner

    def observed_open_directory(directory: Any, component: str) -> Any:
        owner = real_open_directory(directory, component)
        owners.append(owner)
        return owner

    def observed_open_regular(directory: Any, component: str) -> Any:
        owner = real_open_regular(directory, component)
        owners.append(owner)
        return owner

    def interrupted_cleanup(native_owners: tuple[Any, ...]) -> BaseException | None:
        nonlocal interrupted
        result = real_cleanup(native_owners)
        if len(native_owners) == 3 and not interrupted:
            interrupted = True
            raise interruption
        return result

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            boot_id_path,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_root_directory",
            side_effect=observed_open_root,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_child_directory",
            side_effect=observed_open_directory,
        ),
        patch(
            "scripts.verify_trusted_time_images._native_open_child_regular",
            side_effect=observed_open_regular,
        ),
        patch(
            "scripts.verify_trusted_time_images._cleanup_native_owned_descriptors",
            side_effect=interrupted_cleanup,
        ),
        pytest.raises(KeyboardInterrupt) as captured,
    ):
        _current_boot_session_id()

    assert captured.value is interruption
    assert interrupted
    assert owners
    assert all(owner.closed for owner in owners)


def test_darwin_boot_session_identity_uses_isolated_canonical_sysctl() -> None:
    completed = _bytes_result(
        ("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"),
        0,
        b"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\n",
        b"",
    )
    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "darwin"),
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            return_value=completed,
        ) as run,
    ):
        assert _current_boot_session_id() == DARWIN_BOOT_SESSION_ID

    run.assert_called_once_with(
        ("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"),
        cwd=ROOT,
        environment={"LC_ALL": "C", "PATH": os.defpath},
        timeout_seconds=5,
        maximum_stdout_bytes=64,
        maximum_stderr_bytes=256,
    )


@pytest.mark.parametrize(
    "encoded_boot_id",
    [
        b"",
        b"00000000-0000-0000-0000-000000000000\n",
        b"11111111-2222-3333-4444-555555555555\n\n",
        b"11111111-2222-3333-4444-55555555555g\n",
    ],
)
def test_linux_boot_session_identity_rejects_malformed_source(
    tmp_path: Path,
    encoded_boot_id: bytes,
) -> None:
    boot_id_path = tmp_path / "boot_id"
    boot_id_path.write_bytes(encoded_boot_id)

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "linux"),
        patch(
            "scripts.verify_trusted_time_images._LINUX_BOOT_ID_PATH",
            boot_id_path,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()


def test_boot_session_identity_fails_closed_on_sysctl_error_or_unknown_platform() -> None:
    failed = _bytes_result(
        ("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"),
        1,
        b"",
        b"denied\n",
    )
    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "darwin"),
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            return_value=failed,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()

    with (
        patch("scripts.verify_trusted_time_images.sys.platform", "freebsd"),
        pytest.raises(TrustedTimeImageVerificationError, match="identity is unavailable"),
    ):
        _current_boot_session_id()


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {
        "GIT_AUTHOR_EMAIL": "trusted-time-tests@example.invalid",
        "GIT_AUTHOR_NAME": "Trusted Time Tests",
        "GIT_COMMITTER_EMAIL": "trusted-time-tests@example.invalid",
        "GIT_COMMITTER_NAME": "Trusted Time Tests",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": "/tmp",
    }
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _prepare_reviewed_git_repository(root: Path) -> Path:
    _git(root, "init", "--quiet")
    (root / ".gitignore").write_text("*.key\n", encoding="utf-8")
    (root / "Dockerfile").write_text(
        "# syntax=docker/dockerfile:1.7@sha256:"
        "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e\n"
        "FROM scratch\n",
        encoding="utf-8",
    )
    packages = root / "packages"
    packages.mkdir()
    tracked = packages / "tracked.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "fixture")
    return tracked


def _prepare_operator_authority_git_repository(
    root: Path,
    payload: bytes = b"reviewed operator authority\n",
) -> tuple[Path, str]:
    _git(root, "init", "--quiet")
    authority = root / OPERATOR_AUTHORITY_RELATIVE_PATH
    authority.parent.mkdir(parents=True)
    authority.write_bytes(payload)
    authority.chmod(0o644)
    _git(root, "add", OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix())
    _git(root, "commit", "--quiet", "-m", "operator authority")
    return authority, _git(root, "rev-parse", "HEAD").stdout.strip()


def _reviewed_git_root(root: Path) -> tuple[Any, Any, Any]:
    return (
        patch("scripts.verify_trusted_time_images.ROOT", root),
        patch(
            "scripts.verify_trusted_time_images._REVIEWED_FIXED_RELATIVE_PATHS",
            ("Dockerfile",),
        ),
        patch(
            "scripts.verify_trusted_time_images._REVIEWED_DIRECTORY_RELATIVE_PATHS",
            ("packages",),
        ),
    )


def test_reviewed_inputs_bind_launch_entrypoint_and_strict_environment_loader() -> None:
    reviewed = set(_reviewed_input_paths())

    assert all(ROOT / relative in reviewed for relative in NATIVE_BUILD_CONTEXT_RELATIVE_PATHS)
    assert set(NATIVE_BUILD_CONTEXT_RELATIVE_PATHS).issubset(
        image_verifier._BUILD_CONTEXT_FIXED_RELATIVE_PATHS
    )
    assert ROOT / "Makefile" in reviewed
    assert ROOT / "infra" / "docker" / "trusted-time.Dockerfile.dockerignore" in reviewed
    assert ROOT / "scripts" / "credential_env.py" in reviewed
    assert ROOT / "scripts" / "enroll_trusted_time_head_anchor.py" in reviewed
    assert ROOT / "scripts" / "start_trusted_time_supervisor.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_action_topology_fence.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_active_controller.py" in reviewed
    assert (
        ROOT / "scripts" / "trusted_time_post_enrollment_active_controller_admission.py" in reviewed
    )
    assert ROOT / "scripts" / "trusted_time_post_enrollment_claimed_fence.py" in reviewed
    assert (
        ROOT / "scripts" / "trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py"
        in reviewed
    )
    assert ROOT / "scripts" / "trusted_time_post_enrollment_graceful_stop_lifecycle.py" in reviewed
    assert (
        image_verifier._REVIEWED_FIXED_RELATIVE_PATHS.count(
            "scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py"
        )
        == 1
    )
    assert (
        ROOT / "scripts" / "trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
        in reviewed
    )
    assert (
        image_verifier._REVIEWED_FIXED_RELATIVE_PATHS.count(
            "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py"
        )
        == 1
    )
    assert ROOT / "scripts" / "trusted_time_post_enrollment_controller_outcome.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_evidence.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_execution_admission.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_graceful_stop.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_host_orchestrator.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_outcome.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_persistent_topology.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_shutdown_locator.py" in reviewed
    assert (
        ROOT / "scripts" / "trusted_time_post_enrollment_sequence_one_reauthentication.py"
        in reviewed
    )
    assert ROOT / "scripts" / "trusted_time_post_enrollment_sequence_two_verifier.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_staged_topology.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_staging.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_start.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_topology.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_topology_fence.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_topology_reader.py" in reviewed
    assert ROOT / "apps" / "trusted_time_supervisor" / "head_anchor_attempt.py" in reviewed
    assert ROOT / "apps" / "trusted_time_supervisor" / "head_anchor_worker.py" in reviewed
    assert ROOT / "apps" / "trusted_time_supervisor" / "post_enrollment_release.py" in reviewed
    assert (
        ROOT / "apps" / "trusted_time_supervisor" / "post_enrollment_sequence_two_ready.py"
        in reviewed
    )
    assert (
        ROOT / "apps" / "trusted_time_supervisor" / "post_enrollment_runtime_state.py" in reviewed
    )


@pytest.mark.parametrize(
    "relative_path",
    (
        "infra/trusted-time/source-authority.json",
        "infra/trusted-time/chrony.conf",
        "packages/persistence/certs/supabase-prod-ca-2021.crt",
    ),
)
def test_first_enrollment_authority_inputs_are_directly_head_readable(
    relative_path: str,
) -> None:
    payload = b"reviewed authority input\n"
    snapshot = {relative_path: (0o100644, payload)}

    with patch(
        "scripts.verify_trusted_time_images._head_reviewed_input_snapshot",
        return_value=snapshot,
    ):
        assert _head_reviewed_input_payload("a" * 40, relative_path, environment={}) == payload


def test_operator_authority_uses_exact_native_git_transactions_without_legacy_runner() -> None:
    revision = "a" * 40
    object_id = "b" * 40
    payload = b"reviewed operator authority\n"
    observed: list[
        tuple[
            tuple[str, ...],
            str,
            tuple[tuple[str, str], ...],
            bytes,
            int,
            int,
            int,
        ]
    ] = []

    def native_runner(
        argv: tuple[str, ...],
        cwd: str,
        environment: tuple[tuple[str, str], ...],
        stdin: bytes,
        stdout_cap: int,
        stderr_cap: int,
        timeout_ns: int,
    ) -> tuple[tuple[str, ...], int, bytes, bytes]:
        observed.append(
            (
                argv,
                cwd,
                environment,
                stdin,
                stdout_cap,
                stderr_cap,
                timeout_ns,
            )
        )
        return _operator_authority_native_result(
            argv,
            call_number=len(observed),
            revision=revision,
            object_id=object_id,
            payload=payload,
        )

    with (
        patch(
            "scripts.verify_trusted_time_images._run_bounded_process",
            side_effect=native_runner,
        ) as native,
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=AssertionError("legacy subprocess authority reached"),
        ) as legacy,
    ):
        assert _head_reviewed_operator_authority_object(revision) == (
            "100644",
            object_id,
            payload,
        )

    exact_cwd = os.fspath(ROOT.resolve(strict=True))
    revision_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "rev-parse",
        "--verify",
        f"{revision}^{{commit}}",
    )
    tree_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "ls-tree",
        "-z",
        "--full-tree",
        revision,
        "--",
        OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix(),
    )
    blob_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "cat-file",
        "--batch",
    )
    assert observed == [
        (
            revision_argv,
            exact_cwd,
            NATIVE_OPERATOR_GIT_ENVIRONMENT,
            b"",
            64,
            16_384,
            5_000_000_000,
        ),
        (
            tree_argv,
            exact_cwd,
            NATIVE_OPERATOR_GIT_ENVIRONMENT,
            b"",
            1_024,
            16_384,
            5_000_000_000,
        ),
        (
            blob_argv,
            exact_cwd,
            NATIVE_OPERATOR_GIT_ENVIRONMENT,
            object_id.encode("ascii") + b"\n",
            4_353,
            16_384,
            5_000_000_000,
        ),
    ]
    assert native.call_count == 3
    legacy.assert_not_called()


@pytest.mark.parametrize("phase", (1, 2, 3))
@pytest.mark.parametrize(
    "mutation",
    (
        "outer-list",
        "wrong-length",
        "equal-distinct-argv",
        "argv-list",
        "boolean-returncode",
        "mutable-stdout",
        "mutable-stderr",
    ),
)
def test_operator_authority_rejects_malformed_native_result(
    phase: int,
    mutation: str,
) -> None:
    revision = "a" * 40
    object_id = "b" * 40
    payload = b"reviewed operator authority\n"
    call_count = 0

    def native_runner(
        argv: tuple[str, ...],
        _cwd: str,
        _environment: tuple[tuple[str, str], ...],
        _stdin: bytes,
        _stdout_cap: int,
        _stderr_cap: int,
        _timeout_ns: int,
    ) -> object:
        nonlocal call_count
        call_count += 1
        valid = _operator_authority_native_result(
            argv,
            call_number=call_count,
            revision=revision,
            object_id=object_id,
            payload=payload,
        )
        if call_count != phase:
            return valid
        if mutation == "outer-list":
            return list(valid)
        if mutation == "wrong-length":
            return valid[:3]
        if mutation == "equal-distinct-argv":
            copied_argv = tuple(item for item in argv)
            assert copied_argv == argv and copied_argv is not argv
            return _replace_tuple_slot(valid, 0, copied_argv)
        if mutation == "argv-list":
            return _replace_tuple_slot(valid, 0, list(argv))
        if mutation == "boolean-returncode":
            return _replace_tuple_slot(valid, 1, False)
        if mutation == "mutable-stdout":
            return _replace_tuple_slot(valid, 2, bytearray(valid[2]))
        if mutation == "mutable-stderr":
            return _replace_tuple_slot(valid, 3, memoryview(valid[3]))
        raise AssertionError("unreviewed malformed-result mutation")

    with (
        patch(
            "scripts.verify_trusted_time_images._run_bounded_process",
            side_effect=native_runner,
        ) as native,
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=AssertionError("legacy subprocess authority reached"),
        ) as legacy,
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(revision)

    assert native.call_count == phase
    legacy.assert_not_called()


@pytest.mark.parametrize("phase", (1, 2, 3))
@pytest.mark.parametrize(
    "error_type",
    (TimeoutError, OverflowError, OSError, RuntimeError, TypeError, ValueError, MemoryError),
)
def test_operator_authority_normalizes_native_process_failure(
    phase: int,
    error_type: type[Exception],
) -> None:
    revision = "a" * 40
    object_id = "b" * 40
    payload = b"reviewed operator authority\n"
    call_count = 0

    def native_runner(
        argv: tuple[str, ...],
        _cwd: str,
        _environment: tuple[tuple[str, str], ...],
        _stdin: bytes,
        _stdout_cap: int,
        _stderr_cap: int,
        _timeout_ns: int,
    ) -> tuple[tuple[str, ...], int, bytes, bytes]:
        nonlocal call_count
        call_count += 1
        if call_count == phase:
            raise error_type("native Git transaction failed")
        return _operator_authority_native_result(
            argv,
            call_number=call_count,
            revision=revision,
            object_id=object_id,
            payload=payload,
        )

    with (
        patch(
            "scripts.verify_trusted_time_images._run_bounded_process",
            side_effect=native_runner,
        ) as native,
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=AssertionError("legacy subprocess authority reached"),
        ) as legacy,
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(revision)

    assert native.call_count == phase
    legacy.assert_not_called()


@pytest.mark.parametrize("phase", (1, 2, 3))
def test_operator_authority_preserves_asynchronous_native_failure(phase: int) -> None:
    revision = "a" * 40
    object_id = "b" * 40
    payload = b"reviewed operator authority\n"
    call_count = 0

    def native_runner(
        argv: tuple[str, ...],
        _cwd: str,
        _environment: tuple[tuple[str, str], ...],
        _stdin: bytes,
        _stdout_cap: int,
        _stderr_cap: int,
        _timeout_ns: int,
    ) -> tuple[tuple[str, ...], int, bytes, bytes]:
        nonlocal call_count
        call_count += 1
        if call_count == phase:
            raise KeyboardInterrupt
        return _operator_authority_native_result(
            argv,
            call_number=call_count,
            revision=revision,
            object_id=object_id,
            payload=payload,
        )

    with (
        patch(
            "scripts.verify_trusted_time_images._run_bounded_process",
            side_effect=native_runner,
        ) as native,
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=AssertionError("legacy subprocess authority reached"),
        ) as legacy,
        pytest.raises(KeyboardInterrupt),
    ):
        _head_reviewed_operator_authority_object(revision)

    assert native.call_count == phase
    legacy.assert_not_called()


def test_operator_authority_definition_time_root_rejects_path_a_b_relabel(
    tmp_path: Path,
) -> None:
    alternate_root = tmp_path.resolve(strict=True)
    mutable_root = Path(os.fspath(ROOT))
    original_raw_paths = cast(Any, mutable_root)._raw_paths
    original_string = os.fspath(mutable_root)
    object.__setattr__(mutable_root, "_raw_paths", [os.fspath(alternate_root)])
    object.__setattr__(mutable_root, "_str", os.fspath(alternate_root))
    try:
        with (
            patch("scripts.verify_trusted_time_images.ROOT", mutable_root),
            patch(
                "scripts.verify_trusted_time_images._run_bounded_process",
                side_effect=AssertionError("native Git cwd was redirected"),
            ) as native,
            patch(
                "scripts.verify_trusted_time_images.run_bounded_subprocess",
                side_effect=AssertionError("legacy subprocess authority reached"),
            ) as legacy,
            pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
        ):
            _head_reviewed_operator_authority_object("a" * 40)
    finally:
        object.__setattr__(mutable_root, "_raw_paths", original_raw_paths)
        object.__setattr__(mutable_root, "_str", original_string)

    native.assert_not_called()
    legacy.assert_not_called()


def test_operator_authority_is_read_from_exact_git_blob_not_worktree(
    native_git_root: Path,
) -> None:
    reviewed = b"reviewed operator authority\n"
    authority, revision = _prepare_operator_authority_git_repository(native_git_root, reviewed)
    object_id = _git(
        native_git_root,
        "rev-parse",
        f"{revision}:{OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix()}",
    ).stdout.strip()
    authority.write_bytes(b"mutable worktree substitution\n")

    with patch("scripts.verify_trusted_time_images.ROOT", native_git_root):
        assert _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        ) == (
            "100644",
            object_id,
            reviewed,
        )


def test_operator_authority_reader_rejects_absent_git_path(native_git_root: Path) -> None:
    _git(native_git_root, "init", "--quiet")
    (native_git_root / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(native_git_root, "add", "README.md")
    _git(native_git_root, "commit", "--quiet", "-m", "fixture")
    revision = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_operator_authority_reader_rejects_executable_git_blob(
    native_git_root: Path,
) -> None:
    authority, _ = _prepare_operator_authority_git_repository(native_git_root)
    authority.chmod(0o755)
    _git(native_git_root, "add", OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix())
    _git(
        native_git_root,
        "update-index",
        "--chmod=+x",
        OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix(),
    )
    _git(native_git_root, "commit", "--quiet", "-m", "executable authority")
    revision = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_operator_authority_reader_rejects_symlink_git_blob(native_git_root: Path) -> None:
    _git(native_git_root, "init", "--quiet")
    authority = native_git_root / OPERATOR_AUTHORITY_RELATIVE_PATH
    authority.parent.mkdir(parents=True)
    (authority.parent / "target.json").write_bytes(b"substituted\n")
    authority.symlink_to("target.json")
    _git(native_git_root, "add", "--all")
    _git(native_git_root, "commit", "--quiet", "-m", "symlink authority")
    revision = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_operator_authority_reader_rejects_gitlink(native_git_root: Path) -> None:
    _git(native_git_root, "init", "--quiet")
    (native_git_root / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(native_git_root, "add", "README.md")
    _git(native_git_root, "commit", "--quiet", "-m", "fixture")
    referenced_commit = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()
    _git(
        native_git_root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{referenced_commit},{OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix()}",
    )
    _git(native_git_root, "commit", "--quiet", "-m", "gitlink authority")
    revision = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_operator_authority_reader_requires_exact_commit_revision(
    native_git_root: Path,
) -> None:
    _, revision = _prepare_operator_authority_git_repository(native_git_root)
    tree_id = _git(native_git_root, "rev-parse", f"{revision}^{{tree}}").stdout.strip()
    _git(native_git_root, "tag", "-a", "authority-tag", "-m", "authority tag")
    tag_id = _git(native_git_root, "rev-parse", "authority-tag^{tag}").stdout.strip()

    with patch("scripts.verify_trusted_time_images.ROOT", native_git_root):
        for candidate in (tree_id, tag_id, revision.upper(), "a" * 40):
            with pytest.raises(
                TrustedTimeImageVerificationError,
                match="Git object is unavailable",
            ):
                _head_reviewed_operator_authority_object(
                    candidate,
                    _exact_source_root=os.fspath(native_git_root),
                )


def test_operator_authority_reader_ignores_replace_ref_and_ambient_git_config(
    native_git_root: Path,
) -> None:
    reviewed = b"reviewed operator authority\n"
    authority, approved_revision = _prepare_operator_authority_git_repository(
        native_git_root,
        reviewed,
    )
    authority.write_bytes(b"replacement operator authority\n")
    _git(native_git_root, "add", OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix())
    _git(native_git_root, "commit", "--quiet", "-m", "replacement authority")
    replacement_revision = _git(native_git_root, "rev-parse", "HEAD").stdout.strip()
    _git(native_git_root, "checkout", "--quiet", "--detach", approved_revision)
    _git(native_git_root, "replace", approved_revision, replacement_revision)
    attacker_repository = native_git_root / "attacker"
    attacker_repository.mkdir()
    _prepare_operator_authority_git_repository(
        attacker_repository,
        b"ambient attacker authority\n",
    )

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.replaceRefs",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_DIR": os.fspath(attacker_repository / ".git"),
                "GIT_WORK_TREE": os.fspath(attacker_repository),
            },
        ),
    ):
        assert (
            _head_reviewed_operator_authority_object(
                approved_revision,
                _exact_source_root=os.fspath(native_git_root),
            )[2]
            == reviewed
        )


def test_operator_authority_reader_rejects_environment_override(
    native_git_root: Path,
) -> None:
    _, revision = _prepare_operator_authority_git_repository(native_git_root)
    unsafe_environment = _minimal_git_environment()
    unsafe_environment["GIT_DIR"] = os.fspath(native_git_root / "other.git")

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            environment=unsafe_environment,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_operator_authority_reader_rejects_oversized_blob(native_git_root: Path) -> None:
    _, revision = _prepare_operator_authority_git_repository(native_git_root, b"x" * 4_097)

    with (
        patch("scripts.verify_trusted_time_images.ROOT", native_git_root),
        pytest.raises(TrustedTimeImageVerificationError, match="Git object is unavailable"),
    ):
        _head_reviewed_operator_authority_object(
            revision,
            _exact_source_root=os.fspath(native_git_root),
        )


def test_absent_operator_authority_is_not_a_required_fixed_worktree_input() -> None:
    assert (
        OPERATOR_AUTHORITY_RELATIVE_PATH.as_posix()
        not in image_verifier._REVIEWED_FIXED_RELATIVE_PATHS
    )


def test_trusted_time_dockerignore_is_exact_deny_by_default_allowlist() -> None:
    _validate_trusted_time_dockerignore_contract()


def test_trusted_time_dockerfile_frontend_is_content_addressed() -> None:
    dockerfile = ROOT / "infra" / "docker" / "trusted-time.Dockerfile"
    _validate_trusted_time_dockerfile_frontend(dockerfile.read_bytes())
    with pytest.raises(TrustedTimeImageVerificationError, match="content-addressed"):
        _validate_trusted_time_dockerfile_frontend(
            dockerfile.read_bytes().replace(
                b"docker/dockerfile:1.7@sha256:"
                b"a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
                b"docker/dockerfile:1.7",
                1,
            )
        )


def test_clean_git_gate_rejects_gitignored_build_input(tmp_path: Path) -> None:
    _prepare_reviewed_git_repository(tmp_path)
    (tmp_path / "packages" / "private.key").write_text("canary\n", encoding="utf-8")
    assert _git(tmp_path, "status", "--porcelain=v1").stdout == ""

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(TrustedTimeImageVerificationError, match="reviewed inputs"),
    ):
        _current_clean_git_revision()


def test_clean_git_gate_rejects_info_excluded_build_input(tmp_path: Path) -> None:
    _prepare_reviewed_git_repository(tmp_path)
    exclude = tmp_path / ".git" / "info" / "exclude"
    exclude.write_text("packages/local.py\n", encoding="utf-8")
    (tmp_path / "packages" / "local.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert _git(tmp_path, "status", "--porcelain=v1").stdout == ""

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(TrustedTimeImageVerificationError, match="reviewed inputs"),
    ):
        _current_clean_git_revision()


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_clean_git_gate_rejects_hidden_tracked_blob_drift(
    tmp_path: Path,
    index_flag: str,
) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    _git(tmp_path, "update-index", index_flag, "packages/tracked.py")
    tracked.write_text("VALUE = 9\n", encoding="utf-8")
    assert _git(tmp_path, "status", "--porcelain=v1").stdout == ""

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match=r"clean Git revision|reviewed inputs",
        ),
    ):
        _current_clean_git_revision()


def test_clean_git_gate_rejects_hidden_missing_tracked_input(tmp_path: Path) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    _git(tmp_path, "update-index", "--skip-worktree", "packages/tracked.py")
    tracked.unlink()
    assert _git(tmp_path, "status", "--porcelain=v1").stdout == ""

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match=r"clean Git revision|reviewed inputs",
        ),
    ):
        _current_clean_git_revision()


def test_clean_git_gate_rejects_hidden_mode_drift(tmp_path: Path) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    _git(tmp_path, "config", "core.fileMode", "false")
    tracked.chmod(0o755)
    assert _git(tmp_path, "status", "--porcelain=v1").stdout == ""

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(TrustedTimeImageVerificationError, match="reviewed inputs"),
    ):
        _current_clean_git_revision()


def test_head_blob_comparison_rejects_hidden_bytes_independently_of_sha1_oid(
    tmp_path: Path,
) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _git(tmp_path, "update-index", "--assume-unchanged", "packages/tracked.py")
    tracked.write_text("VALUE = 8\n", encoding="utf-8")

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        pytest.raises(TrustedTimeImageVerificationError, match="reviewed inputs"),
    ):
        _require_head_reviewed_inputs(
            revision,
            environment=_minimal_git_environment(),
        )


def test_git_replace_ref_cannot_substitute_approved_revision(tmp_path: Path) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    approved_revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    tracked.write_text("VALUE = 7\n", encoding="utf-8")
    _git(tmp_path, "add", "packages/tracked.py")
    _git(tmp_path, "commit", "--quiet", "-m", "replacement")
    replacement_revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _git(tmp_path, "checkout", "--quiet", "--detach", approved_revision)
    _git(tmp_path, "replace", approved_revision, replacement_revision)

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with root_patch, fixed_patch, directory_patch:
        assert _current_clean_git_revision() == approved_revision


def test_sealed_build_context_uses_only_head_blobs(tmp_path: Path) -> None:
    tracked = _prepare_reviewed_git_repository(tmp_path)
    revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _git(tmp_path, "update-index", "--assume-unchanged", "packages/tracked.py")
    tracked.write_text("VALUE = 6\n", encoding="utf-8")
    (tmp_path / "packages" / "private.key").write_text("canary\n", encoding="utf-8")

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with (
        root_patch,
        fixed_patch,
        directory_patch,
        patch(
            "scripts.verify_trusted_time_images._BUILD_CONTEXT_FIXED_RELATIVE_PATHS",
            frozenset({"Dockerfile"}),
        ),
        patch(
            "scripts.verify_trusted_time_images._TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH",
            "Dockerfile",
        ),
    ):
        encoded = _sealed_head_build_context(revision)

    with tarfile.open(fileobj=io.BytesIO(encoded), mode="r:") as archive:
        names = set(archive.getnames())
        member = archive.extractfile("packages/tracked.py")
        assert member is not None
        assert member.read() == b"VALUE = 1\n"
    assert "packages/private.key" not in names


def _synthetic_native_build_context_snapshot() -> dict[str, tuple[int, bytes]]:
    snapshot = {
        relative: (0o644, f"exact {relative}\n".encode("ascii"))
        for relative in image_verifier._BUILD_CONTEXT_FIXED_RELATIVE_PATHS
    }
    snapshot[image_verifier._TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH] = (
        0o644,
        image_verifier._TRUSTED_TIME_DOCKERFILE_FRONTEND + b"FROM scratch\n",
    )
    return snapshot


@pytest.mark.parametrize("omitted", NATIVE_BUILD_CONTEXT_RELATIVE_PATHS)
def test_sealed_build_context_rejects_any_native_prerequisite_omission(
    omitted: str,
) -> None:
    snapshot = _synthetic_native_build_context_snapshot()
    del snapshot[omitted]

    with (
        patch(
            "scripts.verify_trusted_time_images._head_reviewed_input_snapshot",
            return_value=snapshot,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="build context"),
    ):
        _sealed_head_build_context("a" * 40)


def test_native_build_context_is_order_independent_and_ignores_unreviewed_addition() -> None:
    snapshot = _synthetic_native_build_context_snapshot()
    reversed_snapshot = dict(reversed(tuple(snapshot.items())))
    with patch(
        "scripts.verify_trusted_time_images._head_reviewed_input_snapshot",
        return_value=snapshot,
    ):
        expected = _sealed_head_build_context("a" * 40)
    reversed_snapshot["native/unreviewed.c"] = (0o644, b"not reviewed\n")
    with patch(
        "scripts.verify_trusted_time_images._head_reviewed_input_snapshot",
        return_value=reversed_snapshot,
    ):
        observed = _sealed_head_build_context("a" * 40)

    assert observed == expected
    with tarfile.open(fileobj=io.BytesIO(observed), mode="r:") as archive:
        names = archive.getnames()
    assert "native/unreviewed.c" not in names
    assert all(relative in names for relative in NATIVE_BUILD_CONTEXT_RELATIVE_PATHS)


def test_head_native_build_context_rejects_symlink_git_entry() -> None:
    object_id = b"a" * 40
    completed = _bytes_result(
        ("git", "ls-tree"),
        0,
        (b"120000 blob " + object_id + b"\tbuild_support/native_image_manifest.py\0"),
        b"",
    )
    with (
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            return_value=completed,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="reviewed inputs"),
    ):
        image_verifier._head_reviewed_input_entries(
            "a" * 40,
            environment=_minimal_git_environment(),
        )


def test_native_build_context_uses_committed_bytes_after_worktree_mutation(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init", "--quiet")
    dockerfile = tmp_path / "Dockerfile"
    native_source = tmp_path / "native" / "owned_file_descriptor.c"
    dockerfile.write_bytes(image_verifier._TRUSTED_TIME_DOCKERFILE_FRONTEND + b"FROM scratch\n")
    native_source.parent.mkdir()
    native_source.write_bytes(b"committed native source\n")
    _git(tmp_path, "add", "Dockerfile", "native/owned_file_descriptor.c")
    _git(tmp_path, "commit", "--quiet", "-m", "native fixture")
    revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _git(tmp_path, "update-index", "--assume-unchanged", "native/owned_file_descriptor.c")
    native_source.write_bytes(b"mutated worktree source\n")

    with (
        patch("scripts.verify_trusted_time_images.ROOT", tmp_path),
        patch(
            "scripts.verify_trusted_time_images._REVIEWED_FIXED_RELATIVE_PATHS",
            ("Dockerfile", "native/owned_file_descriptor.c"),
        ),
        patch(
            "scripts.verify_trusted_time_images._REVIEWED_DIRECTORY_RELATIVE_PATHS",
            (),
        ),
        patch(
            "scripts.verify_trusted_time_images._BUILD_CONTEXT_FIXED_RELATIVE_PATHS",
            frozenset({"Dockerfile", "native/owned_file_descriptor.c"}),
        ),
        patch(
            "scripts.verify_trusted_time_images._TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH",
            "Dockerfile",
        ),
    ):
        encoded = _sealed_head_build_context(revision)

    with tarfile.open(fileobj=io.BytesIO(encoded), mode="r:") as archive:
        member = archive.extractfile("native/owned_file_descriptor.c")
        assert member is not None
        assert member.read() == b"committed native source\n"


def test_clean_git_gate_parses_nul_delimited_unusual_tracked_name(tmp_path: Path) -> None:
    _prepare_reviewed_git_repository(tmp_path)
    unusual = tmp_path / "packages" / "tab\tline\n.py"
    unusual.write_text("VALUE = 3\n", encoding="utf-8")
    _git(tmp_path, "add", "packages")
    _git(tmp_path, "commit", "--quiet", "-m", "unusual name")

    root_patch, fixed_patch, directory_patch = _reviewed_git_root(tmp_path)
    with root_patch, fixed_patch, directory_patch:
        assert _current_clean_git_revision() == _git(tmp_path, "rev-parse", "HEAD").stdout.strip()


def test_image_build_git_gate_requires_stable_clean_worktree() -> None:
    git_revision = "a" * 40
    revision = _bytes_result(
        ("git", "rev-parse"),
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    clean = _bytes_result(("git", "status"), 0, b"", b"")

    with (
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=(revision, clean, clean, revision),
        ) as run,
        patch("scripts.verify_trusted_time_images._require_ordinary_git_index_flags"),
        patch("scripts.verify_trusted_time_images._require_head_reviewed_inputs") as tracked,
    ):
        assert _current_clean_git_revision() == git_revision

    assert run.call_count == 4
    assert all(
        call.kwargs["environment"]
        == {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "TMPDIR": "/tmp",
        }
        for call in run.call_args_list
    )
    assert [call.kwargs["maximum_stdout_bytes"] for call in run.call_args_list] == [
        64,
        65_536,
        65_536,
        64,
    ]
    assert all(call.kwargs["maximum_stderr_bytes"] == 16_384 for call in run.call_args_list)
    tracked.assert_called_once_with(
        git_revision,
        environment={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "TMPDIR": "/tmp",
        },
    )


@pytest.mark.parametrize(
    "status_output",
    [
        " M scripts/verify_trusted_time_images.py\n",
        "M  scripts/verify_trusted_time_images.py\n",
        "?? untracked-relevant.py\n",
    ],
)
def test_image_build_git_gate_rejects_any_dirty_worktree(status_output: str) -> None:
    git_revision = "a" * 40
    revision = _bytes_result(
        ("git", "rev-parse"),
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    dirty = _bytes_result(("git", "status"), 0, status_output.encode(), b"")

    with (
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=(revision, dirty, revision),
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="clean Git revision"),
    ):
        _current_clean_git_revision()


def test_image_build_git_gate_rejects_worktree_drift_after_head_input_check() -> None:
    git_revision = "a" * 40
    revision = _bytes_result(
        ("git", "rev-parse"),
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    clean = _bytes_result(("git", "status"), 0, b"", b"")
    dirty = _bytes_result(
        ("git", "status"),
        0,
        b"?? late-untracked-relevant.py\n",
        b"",
    )

    with (
        patch(
            "scripts.verify_trusted_time_images.run_bounded_subprocess",
            side_effect=(revision, clean, dirty, revision),
        ),
        patch("scripts.verify_trusted_time_images._require_ordinary_git_index_flags"),
        patch("scripts.verify_trusted_time_images._require_head_reviewed_inputs"),
        pytest.raises(TrustedTimeImageVerificationError, match="clean Git revision"),
    ):
        _current_clean_git_revision()


def _write_admission(tmp_path: Path) -> tuple[Path, Path, int]:
    ignored_root = tmp_path / "artifacts"
    path = ignored_root / "trusted-time" / "image-admission.json"
    created_monotonic_ns = 10_000_000_000
    write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=SOURCE_ID,
            supervisor_id=SUPERVISOR_ID,
        ),
        git_revision="a" * 40,
        supervisor_executable_import_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
        monotonic_ns=created_monotonic_ns,
    )
    return path, ignored_root, created_monotonic_ns


def _source_inspection() -> image_verifier._ImageInspectionProjection:
    return image_verifier._make_image_inspection_projection(
        image_id=SOURCE_ID,
        user="10001:10001",
        entrypoint=("/usr/sbin/chronyd",),
        command=(
            "-x",
            "-d",
            "-U",
            "-f",
            "/etc/autoquant/trusted-time/chrony.conf",
        ),
        environment=("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",),
        working_directory="/",
    )


def _supervisor_inspection() -> image_verifier._ImageInspectionProjection:
    return image_verifier._make_image_inspection_projection(
        image_id=SUPERVISOR_ID,
        user="10001:10001",
        entrypoint=None,
        command=(
            "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
            "supervisor",
        ),
        environment=(
            "PATH=/opt/autoquant/trusted-time/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8",
            "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
            "PYTHON_VERSION=3.12.13",
            "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
            "LD_LIBRARY_PATH=",
            "LD_PRELOAD=",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONUNBUFFERED=1",
            "UV_COMPILE_BYTECODE=0",
            "UV_NO_DEV=1",
            "UV_NO_SYNC=1",
            "UV_PROJECT_ENVIRONMENT=/opt/autoquant/trusted-time",
        ),
        working_directory="/",
    )


def _image_inspection_receipt(
    inspection: image_verifier._ImageInspectionProjection,
    *,
    exposed_ports: object = None,
    healthcheck: object = None,
    shell: object = None,
    volumes: object = None,
) -> str:
    return (
        json.dumps(
            {
                "cmd": (
                    None
                    if tuple.__getitem__(inspection, 4) is None
                    else list(cast(tuple[str, ...], tuple.__getitem__(inspection, 4)))
                ),
                "entrypoint": (
                    None
                    if tuple.__getitem__(inspection, 3) is None
                    else list(cast(tuple[str, ...], tuple.__getitem__(inspection, 3)))
                ),
                "env": (
                    None
                    if tuple.__getitem__(inspection, 5) is None
                    else list(cast(tuple[str, ...], tuple.__getitem__(inspection, 5)))
                ),
                "exposed_ports": exposed_ports,
                "healthcheck": healthcheck,
                "id": tuple.__getitem__(inspection, 1),
                "shell": shell,
                "user": tuple.__getitem__(inspection, 2),
                "volumes": volumes,
                "working_dir": tuple.__getitem__(inspection, 6),
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def test_image_inspection_uses_one_pinned_scalar_projection() -> None:
    assert image_verifier._IMAGE_INSPECTION_FORMAT == (
        '{"cmd":{{json (index .Config "Cmd")}},'
        '"entrypoint":{{json (index .Config "Entrypoint")}},'
        '"env":{{json (index .Config "Env")}},'
        '"exposed_ports":{{json (index .Config "ExposedPorts")}},'
        '"healthcheck":{{json (index .Config "Healthcheck")}},"id":{{json .Id}},'
        '"shell":{{json (index .Config "Shell")}},'
        '"user":{{json (index .Config "User")}},'
        '"volumes":{{json (index .Config "Volumes")}},'
        '"working_dir":{{json (index .Config "WorkingDir")}}}'
    )
    expected = _source_inspection()
    with patch(
        "scripts.verify_trusted_time_images._docker",
        return_value=_immutable_docker_result(_image_inspection_receipt(expected)),
    ) as docker:
        observed = image_verifier._inspection(
            SOURCE_ID,
            environment={"PATH": "/approved/bin"},
        )

    assert observed == expected
    assert docker.call_args.args == (
        "image",
        "inspect",
        "--format",
        image_verifier._IMAGE_INSPECTION_FORMAT,
        SOURCE_ID,
    )
    assert docker.call_args.kwargs == {"environment": {"PATH": "/approved/bin"}}


@pytest.mark.parametrize(
    "receipt",
    [
        '{"cmd":null,"cmd":null}\n',
        '{"cmd":[1.5]}\n',
        '{"cmd":["\\ud800"]}\n',
        '{"cmd":[{"nested":1,"nested":1}]}\n',
    ],
)
def test_image_inspection_rejects_nonimmutable_or_ambiguous_json(receipt: str) -> None:
    with (
        patch(
            "scripts.verify_trusted_time_images._docker",
            return_value=_immutable_docker_result(receipt),
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="malformed JSON"),
    ):
        image_verifier._inspection(SOURCE_ID)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("exposed_ports", {"123/udp": {}}),
        ("healthcheck", {"Test": ["CMD", "true"]}),
        ("shell", ["/bin/sh", "-c"]),
        ("volumes", {"/data": {}}),
    ],
)
def test_image_inspection_rejects_each_forbidden_runtime_surface(
    field_name: str,
    value: object,
) -> None:
    expected = _source_inspection()
    receipt = _image_inspection_receipt(expected, **{field_name: value})
    with (
        patch(
            "scripts.verify_trusted_time_images._docker",
            return_value=_immutable_docker_result(receipt),
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="malformed"),
    ):
        image_verifier._inspection(SOURCE_ID)


def test_image_inspections_accept_exact_nonroot_outbound_only_contract() -> None:
    validate_source_inspection(_source_inspection())
    validate_supervisor_inspection(_supervisor_inspection())


@pytest.mark.parametrize(
    ("source", "field_name", "value"),
    [
        (True, "user", "0:0"),
        (True, "entrypoint", ("/bin/sh",)),
        (True, "command", ("-d",)),
        (True, "environment", ("PATH=/forged",)),
        (True, "working_directory", "/workspace"),
        (False, "user", "root"),
        (False, "command", ("autoquant-trader",)),
        (False, "environment", ("PATH=/forged",)),
        (False, "working_directory", ""),
    ],
)
def test_image_inspections_reject_identity_command_or_port_drift(
    source: bool,
    field_name: str,
    value: object,
) -> None:
    field_index = {
        "user": 2,
        "entrypoint": 3,
        "command": 4,
        "environment": 5,
        "working_directory": 6,
    }[field_name]
    inspection = _replace_tuple_slot(
        _source_inspection() if source else _supervisor_inspection(),
        field_index,
        value,
    )

    with pytest.raises(TrustedTimeImageVerificationError):
        if source:
            validate_source_inspection(inspection)
        else:
            validate_supervisor_inspection(inspection)


@pytest.mark.parametrize(
    "environment_entry",
    [
        "AQT_DATABASE_URL=secret",
        "AQT_TRUSTED_TIME_DATABASE_URL_FILE=/secret",
        "ALPACA_PAPER_API_SECRET=secret",
        "ETRADE_PRODUCTION_API_SECRET=secret",
        "SENTRY_DSN=secret",
    ],
)
def test_image_inspection_rejects_embedded_secret_material(
    environment_entry: str,
) -> None:
    exact = _supervisor_inspection()
    exact_environment = tuple.__getitem__(exact, 5)
    assert type(exact_environment) is tuple
    inspection = _replace_tuple_slot(
        exact,
        5,
        (*exact_environment, environment_entry),
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="configuration drifted"):
        validate_supervisor_inspection(inspection)


def test_runtime_versions_require_exact_chrony_48_and_source_nts_feature() -> None:
    validate_chronyd_version(
        0,
        "chronyd (chrony) version 4.8 (+CMDMON +NTP +NTS +PRIVDROP)\n",
        "",
    )
    validate_chronyc_version(0, "chronyc (chrony) version 4.8 (-READLINE)\n", "")

    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(0, "chronyd (chrony) version 4.8 (+NTP)\n", "")
    with pytest.raises(TrustedTimeImageVerificationError, match=r"version 4\.8"):
        validate_chronyc_version(0, "chronyc (chrony) version 4.9\n", "")
    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(
            0,
            "prefix chronyd (chrony) version 4.8 (+NTP +NTS)\n",
            "",
        )
    with pytest.raises(TrustedTimeImageVerificationError, match="NTS-enabled"):
        validate_chronyd_version(0, "chronyd (chrony) version 4.8 (+NTP -NTS)\n", "")


def test_static_client_and_ca_store_probes_require_quiet_success() -> None:
    validate_static_chronyc(0, "", "")
    validate_ca_trust_store(0, "", "")

    with pytest.raises(TrustedTimeImageVerificationError, match="dynamic ELF"):
        validate_static_chronyc(1, "", "")
    with pytest.raises(TrustedTimeImageVerificationError, match="CA trust store"):
        validate_ca_trust_store(0, "unexpected", "")


def test_isolated_base_python_probe_ignores_root_import_shadows(tmp_path: Path) -> None:
    (tmp_path / "struct.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    (tmp_path / "sitecustomize.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    base_python = (Path(sys.prefix) / "bin" / "python").resolve(strict=True)

    completed = subprocess.run(
        (
            os.fspath(base_python),
            "-I",
            "-B",
            "-S",
            "-c",
            "import struct;print(struct.pack('>I', 1).hex())",
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "00000001\n"
    assert completed.stderr == ""


def test_pinned_database_ca_requires_exact_root_owned_read_only_metadata() -> None:
    validate_database_ca_metadata(0, "0:0:444\n", "")

    for output in ("10001:0:444\n", "0:0:644\n", "0:0:444"):
        with pytest.raises(TrustedTimeImageVerificationError, match="metadata drifted"):
            validate_database_ca_metadata(0, output, "")


def test_supervisor_schema_probe_requires_exact_0036_head_and_anchor_relations() -> None:
    assert SUPERVISOR_SCHEMA_CONTRACT_COMMAND == (
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "image-schema-contract",
    )
    exact = json.dumps(
        {
            "catalog_relations": list(EXPECTED_CATALOG_RELATIONS),
            "schema_revision": EXPECTED_SCHEMA_REVISION,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    validate_operational_schema_contract(0, f"{exact}\n", "")

    for changed in (
        exact.replace(EXPECTED_SCHEMA_REVISION, "0035_phase6_time_uncertainty"),
        exact.replace(f',"{EXPECTED_CATALOG_RELATIONS[1]}"', ""),
        exact.replace("]", ',"phase6_trusted_time_head_anchor_extra"]'),
    ):
        with pytest.raises(TrustedTimeImageVerificationError, match="schema contract"):
            validate_operational_schema_contract(0, f"{changed}\n", "")


def test_image_hash_output_binds_config_authority_and_database_ca_bytes() -> None:
    source_output = f"{CONFIG_SHA256}  /etc/autoquant/trusted-time/chrony.conf\n"
    supervisor_output = source_output + (
        f"{AUTHORITY_SHA256}  /etc/autoquant/trusted-time/source-authority.json\n"
        f"{DATABASE_CA_SHA256}  "
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt\n"
    )

    validate_config_hashes(
        source_output=source_output,
        supervisor_output=supervisor_output,
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="bytes drifted"):
        validate_config_hashes(
            source_output=source_output,
            supervisor_output=supervisor_output.replace(AUTHORITY_SHA256, "0" * 64),
        )

    with pytest.raises(TrustedTimeImageVerificationError, match="bytes drifted"):
        validate_config_hashes(
            source_output=source_output,
            supervisor_output=supervisor_output.replace(DATABASE_CA_SHA256, "0" * 64),
        )


def test_secretless_supervisor_requires_exact_sanitized_blocked_payload() -> None:
    payload = {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "reason": "configuration_rejected",
        "service": "trusted-time-supervisor",
        "status": "fatal",
    }

    exact = json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
    validate_secretless_supervisor(2, exact, "")

    payload["readiness_authorized"] = True
    with pytest.raises(TrustedTimeImageVerificationError, match="blocked contract"):
        validate_secretless_supervisor(
            2,
            json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n",
            "",
        )
    with pytest.raises(TrustedTimeImageVerificationError, match="quietly"):
        validate_secretless_supervisor(2, "{}", "secret detail")


def test_image_identity_resolution_requires_one_exact_sha256_id() -> None:
    completed = _immutable_docker_result(f"{SOURCE_ID}\n")
    with patch("scripts.verify_trusted_time_images._docker", return_value=completed):
        assert resolve_image_id(SOURCE_IMAGE) == SOURCE_ID

    malformed = _immutable_docker_result(f"{SOURCE_ID}\n{SUPERVISOR_ID}\n")
    with (
        patch("scripts.verify_trusted_time_images._docker", return_value=malformed),
        pytest.raises(TrustedTimeImageVerificationError, match="one immutable"),
    ):
        resolve_image_id(SOURCE_IMAGE)

    with pytest.raises(TrustedTimeImageVerificationError, match="identities are malformed"):
        TrustedTimeImageIdentities(source_id=SOURCE_ID, supervisor_id=SOURCE_ID)


def test_image_identity_resolution_uses_explicit_docker_environment_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_CONTEXT", "ambient-context-must-not-be-added")
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    observed: list[dict[str, str]] = []

    def fake_run(
        argv: tuple[str, ...],
        **kwargs: object,
    ) -> image_verifier.BoundedSubprocessResult:
        observed.append(cast(dict[str, str], kwargs["environment"]))
        assert kwargs["maximum_stdout_bytes"] == 4 * 1_024 * 1_024
        assert kwargs["maximum_stderr_bytes"] == 1 * 1_024 * 1_024
        assert kwargs["maximum_stdin_bytes"] == 0
        return _bytes_result(argv, 0, f"{SOURCE_ID}\n".encode(), b"")

    with patch(
        "scripts.verify_trusted_time_images.run_bounded_subprocess",
        side_effect=fake_run,
    ):
        assert resolve_image_id(SOURCE_ID, environment=exact_environment) == SOURCE_ID

    assert observed == [exact_environment]
    assert "DOCKER_CONTEXT" not in observed[0]


def test_read_only_image_probe_never_pulls() -> None:
    completed = _immutable_docker_result()

    with patch(
        "scripts.verify_trusted_time_images._docker",
        return_value=completed,
    ) as docker:
        _run_read_only(SOURCE_ID, "/usr/bin/true", environment={"PATH": "/approved/bin"})

    assert docker.call_args.args[:3] == ("run", "--rm", "--pull=never")


def test_verify_images_threads_one_explicit_environment_through_every_helper() -> None:
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    completed = _immutable_docker_result()
    schema_environments: list[tuple[tuple[str, str], ...]] = []

    def schema_probe(
        image: str,
        *command: str,
        environment: tuple[tuple[str, str], ...],
    ) -> image_verifier.BoundedSubprocessResult:
        schema_environments.append(environment)
        argv = (
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--entrypoint",
            command[0],
            image,
            *command[1:],
        )
        return (
            argv,
            0,
            b'{"catalog_relations":["phase6_trusted_time_head_anchor_intents",'
            b'"phase6_trusted_time_head_anchor_receipts"],'
            b'"schema_revision":"0036_phase6_time_anchors"}\n',
            b"",
        )

    with (
        patch(
            "scripts.verify_trusted_time_images.resolve_image_id",
            side_effect=(SOURCE_ID, SUPERVISOR_ID),
        ) as resolve,
        patch(
            "scripts.verify_trusted_time_images._inspection",
            side_effect=(_source_inspection(), _supervisor_inspection()),
        ) as inspect,
        patch(
            "scripts.verify_trusted_time_images._run_read_only",
            return_value=completed,
        ) as run_read_only,
        patch(
            "scripts.verify_trusted_time_images._verify_supervisor_executable_import_manifest",
            return_value=SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256,
        ) as verify_manifest,
        patch("scripts.verify_trusted_time_images._docker", return_value=completed) as docker,
        patch("scripts.verify_trusted_time_images._probe_runtime_topology") as probe,
        patch("scripts.verify_trusted_time_images.validate_chronyd_version"),
        patch("scripts.verify_trusted_time_images.validate_chronyc_version"),
        patch("scripts.verify_trusted_time_images.validate_static_chronyc"),
        patch("scripts.verify_trusted_time_images.validate_ca_trust_store"),
        patch("scripts.verify_trusted_time_images.validate_database_ca_metadata"),
        patch("scripts.verify_trusted_time_images.validate_operational_schema_contract"),
        patch("scripts.verify_trusted_time_images.validate_config_hashes"),
        patch("scripts.verify_trusted_time_images.validate_secretless_supervisor"),
    ):
        verified = image_verifier._verify_images_with_manifest(
            SOURCE_ID,
            SUPERVISOR_ID,
            docker_environment=exact_environment,
            _schema_probe=schema_probe,
        )

    assert image_verifier._verified_image_source_id(verified) == SOURCE_ID
    assert image_verifier._verified_image_supervisor_id(verified) == SUPERVISOR_ID
    expected_environment = tuple(sorted(exact_environment.items()))
    for helper in (resolve, inspect, run_read_only, verify_manifest, docker, probe):
        assert helper.call_count > 0
        assert all(
            call.kwargs["environment"] == expected_environment for call in helper.call_args_list
        )
    assert schema_environments == [expected_environment]
    assert all(
        call.kwargs["environment"] == expected_environment for call in run_read_only.call_args_list
    )
    assert any(
        call.args
        == (
            SUPERVISOR_ID,
            "/usr/local/bin/python",
            "-I",
            "-B",
            "-S",
            "-c",
            image_verifier._STATIC_ELF_CHECK,
        )
        for call in run_read_only.call_args_list
    )
    assert any(
        call.args
        == (
            SUPERVISOR_ID,
            "/usr/local/bin/python",
            "-I",
            "-B",
            "-S",
            "-c",
            image_verifier._CA_STORE_CHECK,
        )
        for call in run_read_only.call_args_list
    )
    assert not any(
        len(call.args) >= 3 and call.args[1:3] == ("/usr/local/bin/python", "-c")
        for call in run_read_only.call_args_list
    )
    assert all(
        "--pull=never" in call.args for call in docker.call_args_list if call.args[0] == "run"
    )
    assert docker.call_args.args == (
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *image_verifier._SECRETLESS_SUPERVISOR_DOCKER_ENVIRONMENT_ARGUMENTS,
        SUPERVISOR_ID,
    )
    assert image_verifier._SECRETLESS_SUPERVISOR_DOCKER_ENVIRONMENT_ARGUMENTS == (
        "--env",
        "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256=" + "0" * 64,
        "--env",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256=" + "0" * 64,
        "--env",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256=" + "0" * 64,
        "--env",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256=" + "0" * 64,
    )


def test_supervisor_executable_import_manifest_is_recomputed_and_exactly_bound() -> None:
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    receipt = (
        json.dumps(
            {
                "manifest_sha256": SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256,
                "schema": image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    read_only_completed = (
        _immutable_docker_result("0:0:444:1:123\n"),
        _immutable_docker_result(
            (
                f"{SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256}  "
                f"{image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH}\n"
            ),
        ),
    )

    with (
        patch(
            "scripts.verify_trusted_time_images._run_read_only",
            side_effect=read_only_completed,
        ) as run_read_only,
        patch(
            "scripts.verify_trusted_time_images._run_rootfs_manifest_verifier",
            return_value=_immutable_docker_result(receipt),
        ) as run_manifest_verifier,
    ):
        observed = image_verifier._verify_supervisor_executable_import_manifest(
            SUPERVISOR_ID,
            environment=exact_environment,
        )

    assert observed == SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
    assert run_read_only.call_args_list[0].args == (
        SUPERVISOR_ID,
        "/usr/bin/stat",
        "-c",
        "%u:%g:%a:%h:%s",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
    )
    assert run_manifest_verifier.call_args.args == (
        SUPERVISOR_ID,
        "-I",
        "-B",
        "-S",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER,
        "verify",
        "/",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
    )
    assert run_read_only.call_args_list[1].args == (
        SUPERVISOR_ID,
        "/usr/bin/sha256sum",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
    )
    assert all(
        call.kwargs["environment"] == tuple(sorted(exact_environment.items()))
        for call in (*run_read_only.call_args_list, run_manifest_verifier.call_args)
    )


@pytest.mark.parametrize("result_name", ["metadata", "verification", "digest"])
def test_manifest_subprocess_results_reject_post_store_relabel(
    result_name: str,
) -> None:
    receipt = (
        '{"manifest_sha256":"'
        + SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
        + '","schema":"'
        + image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA
        + '"}\n'
    )
    target = image_verifier._verify_supervisor_executable_import_manifest
    instructions = list(dis.get_instructions(target))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST" and instruction.argval == result_name
    )
    post_store_offset = instructions[store_index + 1].offset
    rejected: list[image_verifier._ImmutableTextSubprocessResult] = []
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def reject_relabel(_: object, offset: int) -> None:
        if offset == post_store_offset:
            result = sys._getframe(1).f_locals[result_name]
            assert type(result) is tuple
            assert len(result) == 4
            with pytest.raises(AttributeError):
                object.__setattr__(result, "stdout", "forged")
            rejected.append(result)

    sys.monitoring.use_tool_id(tool_id, f"manifest-{result_name}-store-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        reject_relabel,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        with (
            patch(
                "scripts.verify_trusted_time_images._run_read_only",
                side_effect=(
                    _immutable_docker_result("0:0:444:1:123\n"),
                    _immutable_docker_result(
                        f"{SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256}  "
                        f"{image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH}\n"
                    ),
                ),
            ),
            patch(
                "scripts.verify_trusted_time_images._run_rootfs_manifest_verifier",
                return_value=_immutable_docker_result(receipt),
            ),
        ):
            observed = image_verifier._verify_supervisor_executable_import_manifest(
                SUPERVISOR_ID,
                environment={"PATH": "/approved/bin"},
            )
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert observed == SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
    assert len(rejected) == 1


@pytest.mark.parametrize("result_name", ["metadata", "verification", "digest"])
def test_manifest_verifier_rejects_mutable_shaped_subprocess_result(
    result_name: str,
) -> None:
    receipt = (
        '{"manifest_sha256":"'
        + SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
        + '","schema":"'
        + image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA
        + '"}\n'
    )
    exact = {
        "metadata": _immutable_docker_result("0:0:444:1:123\n"),
        "verification": _immutable_docker_result(receipt),
        "digest": _immutable_docker_result(
            f"{SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256}  "
            f"{image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH}\n"
        ),
    }
    exact[result_name] = cast(
        Any,
        subprocess.CompletedProcess(
            ["docker"],
            0,
            tuple.__getitem__(exact[result_name], 2),
            "",
        ),
    )

    with (
        patch(
            "scripts.verify_trusted_time_images._run_read_only",
            side_effect=(exact["metadata"], exact["digest"]),
        ),
        patch(
            "scripts.verify_trusted_time_images._run_rootfs_manifest_verifier",
            return_value=exact["verification"],
        ),
        pytest.raises(TrustedTimeImageVerificationError),
    ):
        image_verifier._verify_supervisor_executable_import_manifest(
            SUPERVISOR_ID,
            environment={"PATH": "/approved/bin"},
        )


def test_manifest_verifier_binds_one_immutable_environment_snapshot() -> None:
    environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved.sock",
        "PATH": "/approved/bin",
    }
    expected = tuple(sorted(environment.items()))
    observed: list[tuple[tuple[str, str], ...]] = []
    receipt = (
        '{"manifest_sha256":"'
        + SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
        + '","schema":"'
        + image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA
        + '"}\n'
    )

    def metadata_then_relabel(*_: object, **kwargs: object) -> object:
        observed.append(cast(tuple[tuple[str, str], ...], kwargs["environment"]))
        environment["DOCKER_HOST"] = "unix:///private/tmp/forged.sock"
        return _immutable_docker_result("0:0:444:1:123\n")

    def verification_then_restore(*_: object, **kwargs: object) -> object:
        observed.append(cast(tuple[tuple[str, str], ...], kwargs["environment"]))
        environment["DOCKER_HOST"] = "unix:///private/tmp/approved.sock"
        return _immutable_docker_result(receipt)

    def digest(*_: object, **kwargs: object) -> object:
        observed.append(cast(tuple[tuple[str, str], ...], kwargs["environment"]))
        return _immutable_docker_result(
            f"{SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256}  "
            f"{image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH}\n"
        )

    def read_only(*args: object, **kwargs: object) -> object:
        if not observed:
            return metadata_then_relabel(*args, **kwargs)
        return digest(*args, **kwargs)

    with (
        patch(
            "scripts.verify_trusted_time_images._run_read_only",
            side_effect=read_only,
        ),
        patch(
            "scripts.verify_trusted_time_images._run_rootfs_manifest_verifier",
            side_effect=verification_then_restore,
        ),
    ):
        manifest_sha256 = image_verifier._verify_supervisor_executable_import_manifest(
            SUPERVISOR_ID,
            environment=environment,
        )

    assert manifest_sha256 == SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
    assert observed == [expected, expected, expected]


@pytest.mark.parametrize(
    "constant_name",
    [
        "SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH",
        "SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER",
        "SUPERVISOR_BASE_PYTHON",
        "SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA",
    ],
)
def test_manifest_verifier_rejects_module_global_contract_relabel(
    constant_name: str,
) -> None:
    with (
        patch.object(image_verifier, constant_name, "/forged"),
        patch("scripts.verify_trusted_time_images._run_read_only") as run,
        pytest.raises(TrustedTimeImageVerificationError, match="contract drifted"),
    ):
        image_verifier._verify_supervisor_executable_import_manifest(
            SUPERVISOR_ID,
            environment={"PATH": "/approved/bin"},
        )

    run.assert_not_called()


def test_rootfs_manifest_verifier_uses_exact_root_isolation_contract() -> None:
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    completed = _immutable_docker_result("receipt\n")

    with patch(
        "scripts.verify_trusted_time_images._docker",
        return_value=completed,
    ) as docker:
        observed = image_verifier._run_rootfs_manifest_verifier(
            SUPERVISOR_ID,
            "-I",
            "-B",
            "-S",
            image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER,
            "verify",
            "/",
            image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
            environment=exact_environment,
        )

    assert observed is completed
    assert docker.call_args.args == (
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "0:0",
        "--entrypoint",
        image_verifier.SUPERVISOR_BASE_PYTHON,
        SUPERVISOR_ID,
        "-I",
        "-B",
        "-S",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER,
        "verify",
        "/",
        image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
    )
    assert docker.call_args.kwargs == {"environment": exact_environment}


def test_rootfs_manifest_verifier_rejects_any_command_drift() -> None:
    with (
        patch("scripts.verify_trusted_time_images._docker") as docker,
        pytest.raises(TrustedTimeImageVerificationError, match="command drifted"),
    ):
        image_verifier._run_rootfs_manifest_verifier(
            SUPERVISOR_ID,
            "-I",
            "-B",
            image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER,
            "verify",
            "/",
            image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH,
            environment={"PATH": "/approved/bin"},
        )

    docker.assert_not_called()


def test_manifest_verifier_base_python_flags_skip_malicious_venv_pth() -> None:
    with tempfile.TemporaryDirectory(prefix=".native-pth-", dir=ROOT) as private:
        private_root = Path(private)
        environment_root = private_root / "venv"
        venv.EnvBuilder(with_pip=False, symlinks=False).create(environment_root)
        base_python = (ROOT / ".venv/bin/python").resolve(strict=True)
        (environment_root / "pyvenv.cfg").write_text(
            f"home = {base_python.parent}\n"
            "include-system-site-packages = false\n"
            f"version = {sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}\n"
            f"executable = {base_python}\n",
            encoding="utf-8",
        )
        python = environment_root / "bin" / "admitted-python"
        shutil.copy2(base_python, python)
        python.chmod(0o700)
        for owned_directory in (private_root, environment_root, python.parent):
            directory_metadata = owned_directory.lstat()
            assert stat.S_ISDIR(directory_metadata.st_mode)
            assert directory_metadata.st_uid in (0, os.geteuid())
            assert directory_metadata.st_mode & 0o022 == 0
        python_metadata = python.lstat()
        assert stat.S_ISREG(python_metadata.st_mode)
        assert python_metadata.st_uid in (0, os.geteuid())
        assert python_metadata.st_nlink == 1
        assert python_metadata.st_mode & 0o111 != 0
        site_packages = (
            environment_root
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        sentinel = private_root / "pth-executed"
        (site_packages / "malicious.pth").write_text(
            f"import pathlib; pathlib.Path({os.fspath(sentinel)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        helper = private_root / "manifest-helper.py"
        helper.write_text("print('manifest helper executed')\n", encoding="utf-8")
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"

        environment_snapshot = tuple(sorted(environment.items()))
        control = _run_bounded_process(
            (os.fspath(python), "-I", "-B", "-c", "pass"),
            os.fspath(private_root),
            environment_snapshot,
            b"",
            1_024,
            1_024,
            5_000_000_000,
        )
        assert control[1] == 0, control
        assert sentinel.read_text(encoding="utf-8") == "executed"
        sentinel.unlink()

        isolated = _run_bounded_process(
            (os.fspath(python), "-I", "-B", "-S", os.fspath(helper)),
            os.fspath(private_root),
            environment_snapshot,
            b"",
            1_024,
            1_024,
            5_000_000_000,
        )
        assert isolated[1] == 0
        assert isolated[2] == b"manifest helper executed\n"
        assert isolated[3] == b""
        assert not sentinel.exists()


@pytest.mark.parametrize(
    ("metadata", "receipt", "digest", "message"),
    [
        ("0:0:644:1:123\n", None, None, "metadata"),
        (
            "0:0:444:1:123\n",
            '{"manifest_sha256":"dddd","schema":"wrong"}\n',
            None,
            "receipt",
        ),
        (
            "0:0:444:1:123\n",
            json.dumps(
                {
                    "manifest_sha256": SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256,
                    "schema": image_verifier.SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            "0" * 64 + "  /etc/autoquant/native/executable-import-manifest.jsonl\n",
            "digest",
        ),
    ],
)
def test_supervisor_executable_import_manifest_rejects_every_unbound_layer(
    metadata: str,
    receipt: str | None,
    digest: str | None,
    message: str,
) -> None:
    read_only_results = [_immutable_docker_result(metadata)]
    if digest is not None:
        read_only_results.append(_immutable_docker_result(digest))
    verification = _immutable_docker_result(receipt if receipt is not None else "")

    with (
        patch(
            "scripts.verify_trusted_time_images._run_read_only",
            side_effect=read_only_results,
        ),
        patch(
            "scripts.verify_trusted_time_images._run_rootfs_manifest_verifier",
            return_value=verification,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match=message),
    ):
        image_verifier._verify_supervisor_executable_import_manifest(
            SUPERVISOR_ID,
            environment={"PATH": "/approved/bin"},
        )


def test_build_uses_one_sealed_context_and_exact_secretless_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AQT_TRUSTED_TIME_DATABASE_URL", "must-not-be-forwarded")
    exact_environment = {"PATH": "/fixed/docker/path"}
    context = b"sealed-head-context"
    source_completed = _immutable_docker_result(f"{SOURCE_ID}\n")
    supervisor_completed = _immutable_docker_result(f"{SUPERVISOR_ID}\n")

    with (
        patch(
            "scripts.verify_trusted_time_images._sealed_head_build_context",
            return_value=context,
        ) as sealed,
        patch(
            "scripts.verify_trusted_time_images._docker",
            side_effect=(source_completed, supervisor_completed),
        ) as docker,
    ):
        identities = build_trusted_time_images(
            "a" * 40,
            docker_environment=exact_environment,
        )

    assert identities == TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    sealed.assert_called_once_with("a" * 40)
    assert docker.call_count == 2
    assert {call.args[5] for call in docker.call_args_list} == {
        "chrony-source",
        "trusted-time-supervisor",
    }
    assert all("--quiet" in call.args for call in docker.call_args_list)
    assert all(call.args[-1] == "-" for call in docker.call_args_list)
    assert all(call.kwargs["stdin_bytes"] == context for call in docker.call_args_list)
    assert all(call.kwargs["environment"] == exact_environment for call in docker.call_args_list)


@pytest.mark.parametrize(
    "completed",
    [
        _immutable_docker_result(""),
        _immutable_docker_result("mutable:tag\n"),
        _immutable_docker_result(f"{SOURCE_ID}\n{SOURCE_ID}\n"),
        _immutable_docker_result(f"{SOURCE_ID}\n", stderr="warning"),
    ],
)
def test_build_rejects_nonexact_immutable_identity_output(
    completed: image_verifier._ImmutableTextSubprocessResult,
) -> None:
    with (
        patch(
            "scripts.verify_trusted_time_images._sealed_head_build_context",
            return_value=b"sealed-head-context",
        ),
        patch("scripts.verify_trusted_time_images._docker", return_value=completed),
        pytest.raises(TrustedTimeImageVerificationError, match="image build failed"),
    ):
        build_trusted_time_images(
            "a" * 40,
            docker_environment={"PATH": "/fixed/docker/path"},
        )


def test_build_workflow_admits_compose_before_any_image_build() -> None:
    events: list[str] = []
    bindings = reviewed_input_bindings()
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )

    def built_images(*_: object, **__: object) -> TrustedTimeImageIdentities:
        events.append("images-built")
        return identities

    def verified_images(*images: str, **_: object) -> image_verifier._VerifiedTrustedTimeImages:
        assert images == (SOURCE_ID, SUPERVISOR_ID)
        events.append("images-verified")
        return image_verifier._make_verified_images(
            source_id=identities.source_id,
            supervisor_id=identities.supervisor_id,
            supervisor_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        )

    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ) as clean_revision,
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ),
        patch(
            "scripts.verify_trusted_time_images.validate_prebuild_compose_contract",
            side_effect=lambda **_kwargs: events.append("compose-admitted"),
        ),
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            side_effect=built_images,
        ),
        patch(
            "scripts.verify_trusted_time_images._verify_images_with_manifest",
            side_effect=verified_images,
        ),
    ):
        assert build_and_verify_images() == identities

    assert events == ["compose-admitted", "images-built", "images-verified"]
    assert clean_revision.call_count == 2


def test_image_admission_rejects_drift_from_captured_build_ids_before_write(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = ignored_root / "trusted-time" / "image-admission.json"
    bindings = reviewed_input_bindings()
    built = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    drifted = replace(built, supervisor_id="sha256:" + "9" * 64)
    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ),
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ),
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract"),
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            return_value=built,
        ),
        patch(
            "scripts.verify_trusted_time_images._verify_images_with_manifest",
            return_value=image_verifier._make_verified_images(
                source_id=drifted.source_id,
                supervisor_id=drifted.supervisor_id,
                supervisor_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
            ),
        ) as verify,
        patch("scripts.verify_trusted_time_images.write_image_admission_artifact") as write,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match="built image identities changed before verification",
        ),
    ):
        build_verify_and_write_image_admission(
            artifact_path,
            ignored_root=ignored_root,
        )

    verify.assert_called_once()
    assert verify.call_args.args == (SOURCE_ID, SUPERVISOR_ID)
    assert "docker_environment" in verify.call_args.kwargs
    write.assert_not_called()


def test_existing_image_readmission_rebuilds_and_reverifies_exact_ids(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = ignored_root / "trusted-time" / "image-admission.json"
    bindings = reviewed_input_bindings()
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    retained = object()
    exact_environment = {"PATH": "/fixed/docker/path"}
    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ) as clean_revision,
        patch(
            "scripts.verify_trusted_time_images._minimal_docker_environment",
            return_value=exact_environment,
        ),
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ) as reviewed,
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract") as compose,
        patch(
            "scripts.verify_trusted_time_images._verify_images_with_manifest",
            return_value=image_verifier._make_verified_images(
                source_id=identities.source_id,
                supervisor_id=identities.supervisor_id,
                supervisor_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
            ),
        ) as verify,
        patch(
            "scripts.verify_trusted_time_images.write_image_admission_artifact",
            return_value=retained,
        ) as write,
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            return_value=identities,
        ) as build,
    ):
        result = verify_and_write_existing_image_admission(
            artifact_path,
            SOURCE_ID,
            SUPERVISOR_ID,
            ignored_root=ignored_root,
        )

    assert result is retained
    build.assert_called_once_with(
        "a" * 40,
        docker_environment=exact_environment,
    )
    compose.assert_called_once_with(
        git_revision="a" * 40,
        docker_environment=exact_environment,
    )
    verify.assert_called_once_with(
        SOURCE_ID,
        SUPERVISOR_ID,
        docker_environment=exact_environment,
    )
    write.assert_called_once_with(
        artifact_path,
        identities,
        git_revision="a" * 40,
        supervisor_executable_import_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        bindings=bindings,
        ignored_root=ignored_root,
    )
    assert clean_revision.call_count == 3
    assert reviewed.call_count == 4


def test_existing_image_readmission_uses_caller_pinned_docker_environment(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = ignored_root / "trusted-time" / "image-admission.json"
    bindings = reviewed_input_bindings()
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    exact_environment = {
        "DOCKER_CONTEXT": "qualified-context",
        "PATH": "/qualified/docker/path",
    }
    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ),
        patch("scripts.verify_trusted_time_images._minimal_docker_environment") as ambient,
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ),
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract") as compose,
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            return_value=identities,
        ) as build,
        patch(
            "scripts.verify_trusted_time_images._verify_images_with_manifest",
            return_value=image_verifier._make_verified_images(
                source_id=identities.source_id,
                supervisor_id=identities.supervisor_id,
                supervisor_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
            ),
        ) as verify,
        patch(
            "scripts.verify_trusted_time_images.write_image_admission_artifact",
            return_value=object(),
        ),
    ):
        verify_and_write_existing_image_admission(
            artifact_path,
            SOURCE_ID,
            SUPERVISOR_ID,
            ignored_root=ignored_root,
            docker_environment=exact_environment,
        )

    ambient.assert_not_called()
    build.assert_called_once_with(
        "a" * 40,
        docker_environment=exact_environment,
    )
    compose.assert_called_once_with(
        git_revision="a" * 40,
        docker_environment=exact_environment,
    )
    verify.assert_called_once_with(
        SOURCE_ID,
        SUPERVISOR_ID,
        docker_environment=exact_environment,
    )


def test_existing_image_readmission_rejects_identity_drift_before_write(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = ignored_root / "trusted-time" / "image-admission.json"
    bindings = reviewed_input_bindings()
    requested = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    drifted = replace(requested, supervisor_id="sha256:" + "9" * 64)
    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ),
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=bindings,
        ),
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract"),
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            return_value=requested,
        ),
        patch(
            "scripts.verify_trusted_time_images._verify_images_with_manifest",
            return_value=image_verifier._make_verified_images(
                source_id=drifted.source_id,
                supervisor_id=drifted.supervisor_id,
                supervisor_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
            ),
        ),
        patch("scripts.verify_trusted_time_images.write_image_admission_artifact") as write,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match="existing image identities changed before admission",
        ),
    ):
        verify_and_write_existing_image_admission(
            artifact_path,
            SOURCE_ID,
            SUPERVISOR_ID,
            ignored_root=ignored_root,
        )

    write.assert_not_called()


def test_existing_image_readmission_rejects_images_not_reproduced_from_reviewed_source(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = ignored_root / "trusted-time" / "image-admission.json"
    requested = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    rebuilt = replace(requested, supervisor_id="sha256:" + "9" * 64)
    with (
        patch(
            "scripts.verify_trusted_time_images._current_clean_git_revision",
            return_value="a" * 40,
        ),
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=reviewed_input_bindings(),
        ),
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract"),
        patch(
            "scripts.verify_trusted_time_images.build_trusted_time_images",
            return_value=rebuilt,
        ),
        patch("scripts.verify_trusted_time_images._verify_images_with_manifest") as verify,
        patch("scripts.verify_trusted_time_images.write_image_admission_artifact") as write,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match="existing images do not match the reviewed source build",
        ),
    ):
        verify_and_write_existing_image_admission(
            artifact_path,
            SOURCE_ID,
            SUPERVISOR_ID,
            ignored_root=ignored_root,
        )

    verify.assert_not_called()
    write.assert_not_called()


@pytest.mark.parametrize("path_kind", ["relative", "outside", "noncanonical"])
def test_build_admission_rejects_invalid_artifact_path_before_git_or_docker(
    tmp_path: Path,
    path_kind: str,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_path = {
        "relative": Path("image-admission.json"),
        "outside": tmp_path / "outside-image-admission.json",
        "noncanonical": ignored_root / "trusted-time" / ".." / "image-admission.json",
    }[path_kind]
    with (
        patch("scripts.verify_trusted_time_images._current_clean_git_revision") as git_revision,
        patch("scripts.verify_trusted_time_images.validate_prebuild_compose_contract") as compose,
        patch("scripts.verify_trusted_time_images.build_trusted_time_images") as build,
        patch("scripts.verify_trusted_time_images.verify_images") as verify,
        pytest.raises(
            TrustedTimeImageVerificationError,
            match="image admission artifact path is invalid",
        ),
    ):
        build_verify_and_write_image_admission(
            artifact_path,
            ignored_root=ignored_root,
        )

    git_revision.assert_not_called()
    compose.assert_not_called()
    build.assert_not_called()
    verify.assert_not_called()


def test_atomic_image_admission_is_canonical_owner_only_and_source_bound(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    admission = load_image_admission_artifact(
        path,
        ignored_root=ignored_root,
        monotonic_ns=created + 1,
    )
    encoded = path.read_bytes()
    payload = json.loads(encoded)

    assert admission.identities == TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    assert admission.boot_session_id == BOOT_SESSION_ID
    assert admission.git_revision == "a" * 40
    assert admission.artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    archive = path.with_name(f"image-admission-{admission.artifact_sha256}.json")
    assert (
        encoded
        == json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert archive.read_bytes() == encoded
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert archive.stat().st_nlink == 1
    assert stat.S_IMODE(ignored_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert payload["inputs"]["source_revision_sha256"] == (
        tuple.__getitem__(reviewed_input_bindings(), 9)
    )
    assert payload["inputs"]["schema_revision"] == "0036_phase6_time_anchors"
    assert payload["contract_version"] == "phase6d-trusted-time-image-admission-v3"
    assert payload["boot_session_id"] == BOOT_SESSION_ID
    assert payload["git_revision"] == "a" * 40
    assert payload["inputs"]["catalog_relations"] == list(EXPECTED_CATALOG_RELATIONS)
    migration = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "versions"
        / "0036_phase6_trusted_time_head_anchors.py"
    )
    assert (
        payload["inputs"]["migration_sha256"] == hashlib.sha256(migration.read_bytes()).hexdigest()
    )
    assert "password" not in encoded.decode().lower()
    assert not tuple(path.parent.glob(".*.tmp"))


@pytest.mark.parametrize(
    "field_name",
    [
        "path",
        "source_id",
        "supervisor_id",
        "boot_session_id",
        "git_revision",
        "source_revision_sha256",
        "supervisor_executable_import_manifest_sha256",
        "artifact_sha256",
        "created_at_utc",
        "created_monotonic_ns",
        "encoded",
        "directory_identity",
        "file_identity",
    ],
)
def test_current_loader_rejects_every_drifted_primitive_snapshot_field(
    tmp_path: Path,
    field_name: str,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    real_loader = image_verifier._load_image_admission_provenance_artifact_with_snapshot
    calls = 0

    def load_with_first_snapshot_drift(
        archive_path: Path,
        *,
        ignored_root: Path,
    ) -> tuple[object, image_verifier._TrustedTimeImageAdmissionProvenanceSnapshot]:
        nonlocal calls
        provenance, snapshot = real_loader(
            archive_path,
            ignored_root=ignored_root,
        )
        calls += 1
        if calls != 1:
            return provenance, snapshot
        field_index = {
            "path": 1,
            "source_id": 2,
            "supervisor_id": 3,
            "boot_session_id": 4,
            "git_revision": 5,
            "source_revision_sha256": 6,
            "supervisor_executable_import_manifest_sha256": 7,
            "artifact_sha256": 8,
            "created_at_utc": 9,
            "created_monotonic_ns": 10,
            "encoded": 11,
            "directory_identity": 12,
            "file_identity": 13,
        }[field_name]
        replacement: object = {
            "path": cast(str, tuple.__getitem__(snapshot, 1)) + ".other",
            "source_id": "sha256:" + "3" * 64,
            "supervisor_id": "sha256:" + "4" * 64,
            "boot_session_id": NEXT_BOOT_SESSION_ID,
            "git_revision": "b" * 40,
            "source_revision_sha256": "e" * 64,
            "supervisor_executable_import_manifest_sha256": "e" * 64,
            "artifact_sha256": "f" * 64,
            "created_at_utc": "2026-08-01T12:00:01.000000Z",
            "created_monotonic_ns": cast(int, tuple.__getitem__(snapshot, 10)) + 1,
            "encoded": cast(bytes, tuple.__getitem__(snapshot, 11)) + b" ",
            "directory_identity": (
                *cast(tuple[int, ...], tuple.__getitem__(snapshot, 12))[:-1],
                cast(tuple[int, ...], tuple.__getitem__(snapshot, 12))[-1] + 1,
            ),
            "file_identity": (
                *cast(tuple[int, ...], tuple.__getitem__(snapshot, 13))[:-1],
                cast(tuple[int, ...], tuple.__getitem__(snapshot, 13))[-1] + 1,
            ),
        }[field_name]
        return provenance, cast(
            image_verifier._TrustedTimeImageAdmissionProvenanceSnapshot,
            _replace_tuple_slot(snapshot, field_index, replacement),
        )

    with (
        patch(
            "scripts.verify_trusted_time_images."
            "_load_image_admission_provenance_artifact_with_snapshot",
            side_effect=load_with_first_snapshot_drift,
        ),
        pytest.raises(TrustedTimeImageVerificationError),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 10,
        )


def test_current_loader_rejects_nonexact_private_snapshot_type(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    real_loader = image_verifier._load_image_admission_provenance_artifact_with_snapshot

    def load_with_shaped_tuple(
        archive_path: Path,
        *,
        ignored_root: Path,
    ) -> tuple[object, object]:
        provenance, snapshot = real_loader(
            archive_path,
            ignored_root=ignored_root,
        )

        class ShapedTuple(tuple[object, ...]):
            pass

        return provenance, ShapedTuple(snapshot)

    with (
        patch(
            "scripts.verify_trusted_time_images."
            "_load_image_admission_provenance_artifact_with_snapshot",
            side_effect=load_with_shaped_tuple,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="provenance is malformed"),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_current_loader_never_uses_legacy_mutable_decoder(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    with patch(
        "scripts.verify_trusted_time_images._decode_admission_payload",
        side_effect=AssertionError("legacy mutable decoder reached"),
    ) as decoder:
        admission = load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    decoder.assert_not_called()
    assert admission.artifact_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_current_loader_rejects_structural_decoder_object_relabel(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    real_decoder = image_verifier._decode_structural_admission_payload

    def relabelled_decoder(*args: object, **kwargs: object) -> object:
        admission = real_decoder(*args, **kwargs)
        return replace(admission, git_revision="b" * 40)

    with (
        patch(
            "scripts.verify_trusted_time_images._decode_structural_admission_payload",
            side_effect=relabelled_decoder,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="malformed"),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


@pytest.mark.parametrize("target_kind", ["current", "archive"])
def test_current_loader_rejects_exact_byte_file_replacement_after_first_snapshot(
    tmp_path: Path,
    target_kind: str,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    target = path if target_kind == "current" else archive
    real_loader = image_verifier._load_image_admission_provenance_artifact_with_snapshot
    replaced = False

    def load_then_replace(
        archive_path: Path,
        *,
        ignored_root: Path,
    ) -> tuple[object, image_verifier._TrustedTimeImageAdmissionProvenanceSnapshot]:
        nonlocal replaced
        result = real_loader(archive_path, ignored_root=ignored_root)
        if not replaced:
            replacement = target.with_name(f".{target.name}.replacement")
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(target)
            replaced = True
        return result

    with (
        patch(
            "scripts.verify_trusted_time_images."
            "_load_image_admission_provenance_artifact_with_snapshot",
            side_effect=load_then_replace,
        ),
        pytest.raises(TrustedTimeImageVerificationError),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_current_loader_snapshot_survives_caller_store_domain_relabel(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    exact_artifact_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    def caller() -> tuple[
        object,
        image_verifier._CurrentTrustedTimeImageAdmissionSnapshot,
    ]:
        admission, snapshot = image_verifier._load_current_image_admission_with_snapshot(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )
        return admission, snapshot

    instructions = list(dis.get_instructions(caller))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST" and instruction.argval == "admission"
    )
    post_store_offset = instructions[store_index + 1].offset
    mutated_candidates: list[object] = []

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def mutate_after_store(_: object, offset: int) -> None:
        if offset == post_store_offset:
            admission = sys._getframe(1).f_locals["admission"]
            object.__setattr__(admission, "artifact_sha256", "f" * 64)
            mutated_candidates.append(admission)

    sys.monitoring.use_tool_id(tool_id, "image-admission-return-snapshot-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        mutate_after_store,
    )
    sys.monitoring.set_local_events(
        tool_id,
        caller.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        admission, snapshot = caller()
    finally:
        sys.monitoring.set_local_events(tool_id, caller.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert len(mutated_candidates) == 1
    assert cast(Any, mutated_candidates[0]).artifact_sha256 == "f" * 64
    assert cast(Any, admission).artifact_sha256 == "f" * 64
    assert tuple.__getitem__(snapshot, 10) == exact_artifact_sha256


def test_static_provenance_loader_accepts_stale_cross_boot_exact_archive_only(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive = path.with_name(f"image-admission-{artifact_sha256}.json")

    with patch(
        "scripts.verify_trusted_time_images._current_boot_session_id",
        return_value=NEXT_BOOT_SESSION_ID,
    ):
        provenance = load_image_admission_provenance_artifact(
            archive,
            ignored_root=ignored_root,
        )
        with pytest.raises(TrustedTimeImageVerificationError, match="different boot session"):
            load_image_admission_artifact(
                archive,
                ignored_root=ignored_root,
                monotonic_ns=(created + (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS + 1) * 1_000_000_000),
            )

    assert provenance.artifact_sha256 == artifact_sha256
    assert provenance.encoded == encoded
    assert provenance.path == archive
    assert provenance.admission().artifact_sha256 == artifact_sha256
    _, snapshot = image_verifier._load_image_admission_provenance_artifact_with_snapshot(
        archive,
        ignored_root=ignored_root,
    )
    assert tuple.__getitem__(snapshot, 7) == SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
    with pytest.raises(TrustedTimeImageVerificationError, match="provenance binding"):
        load_image_admission_provenance_artifact(
            path,
            ignored_root=ignored_root,
        )


@pytest.mark.parametrize("mutation", ["tamper", "mode", "replacement"])
def test_static_provenance_loader_rejects_archive_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    path, ignored_root, _ = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    if mutation == "tamper":
        archive.write_bytes(b"x" + encoded[1:])
        archive.chmod(0o600)
    elif mutation == "mode":
        archive.chmod(0o640)
    else:
        replacement = archive.with_name(".replacement-provenance")
        replacement.write_bytes(encoded)
        replacement.chmod(0o600)
        replacement.replace(archive)

    if mutation == "replacement":
        # Replacement before the read is safe because the exact bytes, owner,
        # mode, link count, and content-addressed name are reauthenticated.
        assert (
            load_image_admission_provenance_artifact(
                archive,
                ignored_root=ignored_root,
            ).encoded
            == encoded
        )
    else:
        with pytest.raises(TrustedTimeImageVerificationError):
            load_image_admission_provenance_artifact(
                archive,
                ignored_root=ignored_root,
            )


def test_current_loader_rejects_superseded_v1_admission_without_git_revision(
    tmp_path: Path,
) -> None:
    path, _, created = _write_admission(tmp_path)
    payload = json.loads(path.read_bytes())
    payload["contract_version"] = "phase6d-trusted-time-image-admission-v1"
    del payload["git_revision"]

    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        _decode_admission_payload(
            payload,
            path=path,
            artifact_sha256="f" * 64,
            boot_session_id=BOOT_SESSION_ID,
            monotonic_ns=created + 1,
        )


def test_current_loader_rejects_superseded_v2_admission_without_native_manifest(
    tmp_path: Path,
) -> None:
    path, _, created = _write_admission(tmp_path)
    payload = json.loads(path.read_bytes())
    payload["contract_version"] = "phase6d-trusted-time-image-admission-v2"
    del payload["images"]["supervisor_executable_import_manifest_sha256"]

    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        _decode_admission_payload(
            payload,
            path=path,
            artifact_sha256="f" * 64,
            boot_session_id=BOOT_SESSION_ID,
            monotonic_ns=created + 1,
        )


@pytest.mark.parametrize("mutation", ["missing", "malformed", "extra"])
def test_image_admission_requires_exact_supervisor_executable_manifest_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    path, _, created = _write_admission(tmp_path)
    payload = json.loads(path.read_bytes())
    images = payload["images"]
    if mutation == "missing":
        del images["supervisor_executable_import_manifest_sha256"]
    elif mutation == "malformed":
        images["supervisor_executable_import_manifest_sha256"] = "D" * 64
    else:
        images["unexpected_manifest_alias"] = SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256

    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        _decode_admission_payload(
            payload,
            path=path,
            artifact_sha256="f" * 64,
            boot_session_id=BOOT_SESSION_ID,
            monotonic_ns=created + 1,
        )


@pytest.mark.parametrize(
    "artifact_boot_session",
    [
        "linux:00000000-0000-0000-0000-000000000000",
        "linux:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "freebsd:11111111-2222-3333-4444-555555555555",
        7,
    ],
)
def test_image_admission_rejects_malformed_boot_session_binding(
    tmp_path: Path,
    artifact_boot_session: object,
) -> None:
    path, _, created = _write_admission(tmp_path)
    payload = json.loads(path.read_bytes())
    payload["boot_session_id"] = artifact_boot_session

    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        _decode_admission_payload(
            payload,
            path=path,
            artifact_sha256="f" * 64,
            boot_session_id=BOOT_SESSION_ID,
            monotonic_ns=created + 1,
        )


@pytest.mark.parametrize(
    ("target_kind", "drift_field"),
    [
        ("canonical", "st_mode"),
        ("canonical", "st_uid"),
        ("canonical", "st_nlink"),
        ("canonical", "st_ctime_ns"),
        ("archive", "st_mode"),
        ("archive", "st_uid"),
        ("archive", "st_nlink"),
        ("archive", "st_ctime_ns"),
    ],
)
def test_image_admission_rejects_metadata_drift_during_canonical_or_archive_read(
    tmp_path: Path,
    target_kind: str,
    drift_field: str,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    target = path if target_kind == "canonical" else archive
    target_metadata = target.stat()
    target_identity = (target_metadata.st_dev, target_metadata.st_ino)
    real_fstat = image_verifier._native_fstat
    target_observations = 0

    def drifting_fstat(owner: Any) -> tuple[int, ...]:
        nonlocal target_observations
        observed = real_fstat(owner)
        if stat.S_ISREG(observed[2]) and (observed[0], observed[1]) == target_identity:
            target_observations += 1
            if target_observations == 2:
                values = list(observed)
                index, replacement = {
                    "st_mode": (2, stat.S_IFREG | 0o640),
                    "st_uid": (3, observed[3] + 1),
                    "st_nlink": (5, observed[5] + 1),
                    "st_ctime_ns": (8, observed[8] + 1),
                }[drift_field]
                values[index] = replacement
                return tuple(values)
        return observed

    with (
        patch(
            "scripts.verify_trusted_time_images._native_fstat",
            side_effect=drifting_fstat,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="unavailable"),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_content_addressed_image_admission_archive_is_never_overwritten(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    archive.write_bytes(b"tampered")
    archive.chmod(0o600)

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        write_image_admission_artifact(
            path,
            TrustedTimeImageIdentities(
                source_id=SOURCE_ID,
                supervisor_id=SUPERVISOR_ID,
            ),
            git_revision="a" * 40,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=created,
        )


def test_exact_archive_retry_reestablishes_file_and_directory_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    canonical_path = artifact_directory / "image-admission.json"
    encoded = b'{"exact":true}\n'
    archive_path = canonical_path.with_name(
        f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json"
    )
    real_fsync = os.fsync
    failed_directory_fsync = False

    def fail_first_directory_fsync(descriptor: int) -> None:
        nonlocal failed_directory_fsync
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode) and not failed_directory_fsync:
            failed_directory_fsync = True
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_directory_fsync)
    with pytest.raises(TrustedTimeImageVerificationError, match="archive write failed"):
        image_verifier._retain_content_addressed_image_admission(
            canonical_path,
            encoded,
            ignored_root=ignored_root,
        )

    archive_identity = (archive_path.stat().st_dev, archive_path.stat().st_ino)
    assert archive_path.read_bytes() == encoded

    def fail_retry_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected retry directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_retry_directory_fsync)
    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        image_verifier._retain_content_addressed_image_admission(
            canonical_path,
            encoded,
            ignored_root=ignored_root,
        )

    observed_fsync_kinds: list[str] = []

    def observe_retry_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        observed_fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", observe_retry_fsync)
    retained = image_verifier._retain_content_addressed_image_admission(
        canonical_path,
        encoded,
        ignored_root=ignored_root,
    )

    assert retained == archive_path
    assert observed_fsync_kinds == ["file", "directory"]
    assert (archive_path.stat().st_dev, archive_path.stat().st_ino) == archive_identity
    assert archive_path.read_bytes() == encoded


@pytest.mark.parametrize(
    ("interrupted_creation", "creation_occurrence", "expected_archive_count"),
    (("archive", 1, 0), ("canonical", 2, 1)),
)
def test_image_admission_temporary_owned_fd_call_store_interrupt_cleans_exact_name_and_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted_creation: str,
    creation_occurrence: int,
    expected_archive_count: int,
) -> None:
    target = image_verifier._OwnedTemporaryImageAdmissionArtifact.create
    instructions = list(dis.get_instructions(target))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "_file_owner"
    )
    target_offset = instructions[store_index - 1].offset
    real_open_owned_file = image_verifier._open_owned_file
    temporary_descriptors: list[int] = []

    def observed_open_owned_file(
        path: str | Path,
        *,
        dir_fd: int | None = None,
        exclusive: bool = False,
    ) -> Any:
        owner = real_open_owned_file(path, dir_fd=dir_fd, exclusive=exclusive)
        if exclusive:
            temporary_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(image_verifier, "_open_owned_file", observed_open_owned_file)
    observed_creations = 0
    interrupted = False

    def interrupt_after_fileio_call(_: object, instruction_offset: int) -> None:
        nonlocal interrupted, observed_creations
        if instruction_offset != target_offset:
            return
        observed_creations += 1
        if observed_creations == creation_occurrence:
            interrupted = True
            raise KeyboardInterrupt

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, f"image-admission-{interrupted_creation}-temp-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt_after_fileio_call,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            _write_admission(tmp_path)
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    artifact_directory = tmp_path / "artifacts" / "trusted-time"
    assert interrupted
    assert observed_creations == creation_occurrence
    assert len(list(artifact_directory.glob("image-admission-*.json"))) == (expected_archive_count)
    assert not list(artifact_directory.glob(".*.tmp"))
    assert temporary_descriptors
    for descriptor in temporary_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("relative", [False, True])
def test_image_verifier_owned_descriptor_call_store_interrupt_closes_native_result(
    tmp_path: Path,
    relative: bool,
) -> None:
    target = image_verifier._open_owned_descriptor
    stores = [
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST" and instruction.argval == "owner"
    ]
    parent_owner = target(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        descriptor_root = Path("/dev/fd")
    before = {entry.name for entry in descriptor_root.iterdir()}
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == stores[1 if relative else 0]:
            raise KeyboardInterrupt

    sys.monitoring.use_tool_id(tool_id, "image-verifier-owned-descriptor-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            target(
                "." if relative else tmp_path,
                flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                dir_fd=parent_owner.fileno() if relative else None,
            )
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    gc.collect()
    assert {entry.name for entry in descriptor_root.iterdir()} == before
    parent_owner.close()


def test_image_verifier_owned_descriptor_close_covers_retired_store_edge(
    tmp_path: Path,
) -> None:
    owner = image_verifier._open_owned_descriptor(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    descriptor = owner.fileno()
    target = image_verifier._OwnedFileDescriptor.close
    instructions = list(dis.get_instructions(target))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "value"
    )
    interrupt_offset = instructions[store_index + 1].offset
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == interrupt_offset:
            raise KeyboardInterrupt

    sys.monitoring.use_tool_id(tool_id, "image-verifier-owned-close-store-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            owner.close()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert owner.value == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_second_generation_retains_both_exact_admission_artifacts(tmp_path: Path) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    prior = path.read_bytes()
    prior_archive = path.with_name(f"image-admission-{hashlib.sha256(prior).hexdigest()}.json")

    write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=SOURCE_ID,
            supervisor_id=SUPERVISOR_ID,
        ),
        git_revision="a" * 40,
        supervisor_executable_import_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
        monotonic_ns=created + 1,
    )
    current = path.read_bytes()
    current_archive = path.with_name(f"image-admission-{hashlib.sha256(current).hexdigest()}.json")

    assert current != prior
    assert prior_archive.read_bytes() == prior
    assert current_archive.read_bytes() == current
    assert stat.S_IMODE(prior_archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(current_archive.stat().st_mode) == 0o600


def test_archive_failure_occurs_before_canonical_replacement(tmp_path: Path) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    prior = path.read_bytes()
    candidate_path = ignored_root / "candidate" / "image-admission.json"
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    write_image_admission_artifact(
        candidate_path,
        identities,
        git_revision="a" * 40,
        supervisor_executable_import_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
        monotonic_ns=created + 1,
    )
    candidate = candidate_path.read_bytes()
    conflicting_archive = path.with_name(
        f"image-admission-{hashlib.sha256(candidate).hexdigest()}.json"
    )
    conflicting_archive.write_bytes(b"tampered")
    conflicting_archive.chmod(0o600)

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
        write_image_admission_artifact(
            path,
            identities,
            git_revision="a" * 40,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 1, tzinfo=UTC),
            monotonic_ns=created + 1,
        )

    assert path.read_bytes() == prior


def test_canonical_loader_requires_its_exact_content_addressed_archive(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    encoded = path.read_bytes()
    archive = path.with_name(f"image-admission-{hashlib.sha256(encoded).hexdigest()}.json")
    archive.unlink()

    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_rejects_cross_boot_replay_even_with_fresh_monotonic_age(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    with (
        patch(
            "scripts.verify_trusted_time_images._current_boot_session_id",
            return_value=NEXT_BOOT_SESSION_ID,
        ),
        pytest.raises(
            TrustedTimeImageVerificationError,
            match="different boot session",
        ),
    ):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_rejects_stale_clock_regression_and_noncanonical_tampering(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)

    for observed in (
        created - 1,
        created + (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS + 1) * 1_000_000_000,
    ):
        with pytest.raises(TrustedTimeImageVerificationError, match="stale"):
            load_image_admission_artifact(
                path,
                ignored_root=ignored_root,
                monotonic_ns=observed,
            )

    payload = json.loads(path.read_bytes())
    payload["inputs"]["migration_sha256"] = "0" * 64
    path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    path.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    _write_admission(tmp_path)
    path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    path.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_default_clock_counts_simulated_system_suspend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root = tmp_path / "artifacts"
    path = ignored_root / "trusted-time" / "image-admission.json"
    created = 10_000_000_000
    observations = iter(
        [
            created,
            created + (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS + 1) * 1_000_000_000,
        ]
    )
    monkeypatch.setattr(
        image_verifier,
        "_suspend_aware_monotonic_ns",
        lambda: next(observations),
    )
    write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=SOURCE_ID,
            supervisor_id=SUPERVISOR_ID,
        ),
        git_revision="a" * 40,
        supervisor_executable_import_manifest_sha256=(SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256),
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
    )

    with pytest.raises(TrustedTimeImageVerificationError, match="stale"):
        load_image_admission_artifact(path, ignored_root=ignored_root)


def test_image_admission_rejects_broad_mode_symlink_and_lookalike_path(
    tmp_path: Path,
) -> None:
    path, ignored_root, created = _write_admission(tmp_path)
    path.chmod(0o644)
    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    path.chmod(0o600)
    target = path.with_name("held.json")
    path.replace(target)
    path.symlink_to(target)
    with pytest.raises(TrustedTimeImageVerificationError, match="unavailable"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    lookalike = tmp_path / "lookalike" / "trusted-time" / "image-admission.json"
    lookalike.parent.mkdir(parents=True)
    lookalike.write_bytes(target.read_bytes())
    lookalike.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="path is invalid"):
        load_image_admission_artifact(
            lookalike,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )


def test_image_admission_writer_rejects_symlink_target_and_source_revision_toctou(
    tmp_path: Path,
) -> None:
    path, ignored_root, _ = _write_admission(tmp_path)
    target = path.with_name("held.json")
    path.replace(target)
    path.symlink_to(target)
    identities = TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    bindings = reviewed_input_bindings()
    with pytest.raises(TrustedTimeImageVerificationError, match="target is invalid"):
        write_image_admission_artifact(
            path,
            identities,
            git_revision="a" * 40,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            bindings=bindings,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=1,
        )

    path.unlink()
    changed = cast(
        image_verifier._ReviewedInputBindings,
        _replace_tuple_slot(bindings, 9, "0" * 64),
    )
    with (
        patch(
            "scripts.verify_trusted_time_images.reviewed_input_bindings",
            return_value=changed,
        ),
        pytest.raises(TrustedTimeImageVerificationError, match="changed during admission"),
    ):
        write_image_admission_artifact(
            path,
            identities,
            git_revision="a" * 40,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            bindings=bindings,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=1,
        )


def test_real_topology_probe_uses_one_hardened_shared_socket_and_cleans_up() -> None:
    token = "a" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"
    source_name = f"aqt-trusted-time-admission-{token}-source"
    calls: list[tuple[str, ...]] = []
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    observed_environments: list[object] = []

    def result(
        arguments: tuple[str, ...],
        stdout: str = "",
    ) -> image_verifier._ImmutableTextSubprocessResult:
        return (("docker", *arguments), 0, stdout, "")

    def fake_docker(
        *arguments: str,
        **kwargs: object,
    ) -> image_verifier._ImmutableTextSubprocessResult:
        calls.append(arguments)
        observed_environments.append(kwargs.get("environment"))
        if arguments[:2] == ("volume", "create"):
            return result(arguments, f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                _socket_volume_projection_json(
                    volume_name=volume_name,
                    token=token,
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, "3" * 64 + "\n")
        if arguments[:2] == ("container", "inspect"):
            return result(
                arguments,
                _source_probe_projection_json(
                    image_id=SOURCE_ID,
                    volume_name=volume_name,
                    token=token,
                ),
            )
        if arguments[:2] == ("container", "exec") and "/bin/sh" in arguments:
            return result(arguments, image_verifier._SOCKET_MOUNTINFO_RECEIPT)
        if arguments[:2] == ("container", "exec") and "/bin/stat" in arguments:
            return result(arguments, "10001:10001:750\n")
        if arguments[:2] == ("container", "exec"):
            return result(arguments, "200 OK\n")
        if arguments[:2] == ("run", "--rm") and "/bin/sh" in arguments:
            return result(arguments, image_verifier._SOCKET_MOUNTINFO_RECEIPT)
        if arguments[:2] == ("run", "--rm"):
            return result(arguments, "200 OK\n")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, f"{source_name}\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
    ):
        _probe_runtime_topology(
            SOURCE_ID,
            SUPERVISOR_ID,
            environment=exact_environment,
        )

    source_run = next(call for call in calls if call[:2] == ("run", "--detach"))
    supervisor_runs = [call for call in calls if call[:2] == ("run", "--rm")]
    assert "--pull=never" in source_run
    assert len(supervisor_runs) == 2
    assert all("--pull=never" in call for call in supervisor_runs)
    assert "none" in source_run and "--read-only" in source_run and "ALL" in source_run
    assert SOURCE_ID in source_run
    assert all(SUPERVISOR_ID in call for call in supervisor_runs)
    assert any(volume_name in argument for argument in source_run)
    assert all(any(volume_name in argument for argument in call) for call in supervisor_runs)
    mount_probes = [
        call
        for call in calls
        if "/bin/sh" in call and image_verifier._SOCKET_MOUNTINFO_CHECK in call
    ]
    assert len(mount_probes) == 2
    assert mount_probes[0][:2] == ("container", "exec")
    assert mount_probes[1][:2] == ("run", "--rm")
    assert calls[-2:] == [
        ("container", "rm", "--force", source_name),
        ("volume", "rm", volume_name),
    ]
    assert observed_environments
    assert all(environment == exact_environment for environment in observed_environments)


@pytest.mark.parametrize(
    "completed",
    [
        _immutable_docker_result(returncode=1),
        _immutable_docker_result(),
        _immutable_docker_result("tmpfs:rw:nosuid:nodev\n"),
        _immutable_docker_result(
            image_verifier._SOCKET_MOUNTINFO_RECEIPT,
            stderr="warning",
        ),
    ],
)
def test_effective_socket_mount_probe_rejects_nonexact_noexec_tmpfs_receipt(
    completed: image_verifier._ImmutableTextSubprocessResult,
) -> None:
    with pytest.raises(TrustedTimeImageVerificationError, match="effective noexec tmpfs"):
        image_verifier._validate_socket_mountinfo_probe(
            completed,
            label="trusted-time test",
        )


def test_partial_source_start_still_attempts_known_name_cleanup() -> None:
    token = "b" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"
    source_name = f"aqt-trusted-time-admission-{token}-source"
    calls: list[tuple[str, ...]] = []

    def result(
        arguments: tuple[str, ...],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> image_verifier._ImmutableTextSubprocessResult:
        return (("docker", *arguments), returncode, stdout, stderr)

    def fake_docker(
        *arguments: str,
        **_: object,
    ) -> image_verifier._ImmutableTextSubprocessResult:
        calls.append(arguments)
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=_socket_volume_projection_json(
                    volume_name=volume_name,
                    token=token,
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, returncode=125, stderr="sanitized start failure")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, stdout=f"{source_name}\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, stdout=f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
        pytest.raises(TrustedTimeImageVerificationError, match="source socket probe"),
    ):
        _probe_runtime_topology(SOURCE_ID, SUPERVISOR_ID)

    assert ("container", "rm", "--force", source_name) in calls
    assert calls[-1] == ("volume", "rm", volume_name)


def test_partial_source_start_surfaces_cleanup_failure_without_resource_detail() -> None:
    token = "c" * 32
    volume_name = f"aqt-trusted-time-admission-{token}-socket"
    exact_environment = {
        "DOCKER_HOST": "unix:///private/tmp/approved-docker.sock",
        "PATH": "/approved/bin",
    }
    observed_environments: list[object] = []

    def result(
        arguments: tuple[str, ...],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> image_verifier._ImmutableTextSubprocessResult:
        return (("docker", *arguments), returncode, stdout, stderr)

    def fake_docker(
        *arguments: str,
        **kwargs: object,
    ) -> image_verifier._ImmutableTextSubprocessResult:
        observed_environments.append(kwargs.get("environment"))
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=_socket_volume_projection_json(
                    volume_name=volume_name,
                    token=token,
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, returncode=125, stderr="start failure detail")
        if arguments[:3] == ("container", "rm", "--force"):
            return result(arguments, returncode=1, stderr="remove failure detail")
        if arguments[:2] == ("container", "ls"):
            return result(arguments, stdout="still-present\n")
        if arguments[:2] == ("volume", "rm"):
            return result(arguments, returncode=1, stderr="volume failure detail")
        if arguments[:2] == ("volume", "ls"):
            return result(arguments, stdout=f"{volume_name}\n")
        raise AssertionError(arguments)

    with (
        patch("scripts.verify_trusted_time_images.secrets.token_hex", return_value=token),
        patch("scripts.verify_trusted_time_images._docker", side_effect=fake_docker),
        pytest.raises(
            TrustedTimeImageVerificationError, match="topology probe cleanup failed"
        ) as error,
    ):
        _probe_runtime_topology(
            SOURCE_ID,
            SUPERVISOR_ID,
            environment=exact_environment,
        )

    assert isinstance(error.value.__cause__, TrustedTimeImageVerificationError)
    assert "start failure detail" not in str(error.value)
    assert "remove failure detail" not in str(error.value)
    assert observed_environments
    assert all(environment == exact_environment for environment in observed_environments)
