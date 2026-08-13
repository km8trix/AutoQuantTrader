from __future__ import annotations

import ctypes
import dis
import gc
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

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
    SUPERVISOR_APPLICATION_PYTHON,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
    _build_suspend_aware_monotonic_clock,
    _current_boot_session_id,
    _current_clean_git_revision,
    _DarwinMachTimebaseInfo,
    _decode_admission_payload,
    _head_reviewed_input_payload,
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
    verify_images,
    write_image_admission_artifact,
)

SOURCE_ID = "sha256:" + "1" * 64
SUPERVISOR_ID = "sha256:" + "2" * 64
BOOT_SESSION_ID = "linux:11111111-2222-3333-4444-555555555555"
NEXT_BOOT_SESSION_ID = "linux:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DARWIN_BOOT_SESSION_ID = "darwin:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture(autouse=True)
def _stable_boot_session_identity() -> Iterator[None]:
    with patch(
        "scripts.verify_trusted_time_images._current_boot_session_id",
        return_value=BOOT_SESSION_ID,
    ):
        yield


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
    ):
        assert _current_boot_session_id() == BOOT_SESSION_ID
        assert _current_boot_session_id() == BOOT_SESSION_ID


def test_darwin_boot_session_identity_uses_isolated_canonical_sysctl() -> None:
    completed = subprocess.CompletedProcess(
        ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
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
    failed = subprocess.CompletedProcess(
        ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
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


def _reviewed_git_root(root: Path) -> tuple[object, object, object]:
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
    assert ROOT / "scripts" / "trusted_time_post_enrollment_controller_outcome.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_evidence.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_execution_admission.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_host_orchestrator.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_outcome.py" in reviewed
    assert ROOT / "scripts" / "trusted_time_post_enrollment_persistent_topology.py" in reviewed
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
    snapshot = {ROOT / relative_path: (0o100644, payload)}

    with patch(
        "scripts.verify_trusted_time_images._head_reviewed_input_snapshot",
        return_value=snapshot,
    ):
        assert _head_reviewed_input_payload("a" * 40, relative_path, environment={}) == payload


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
    revision = subprocess.CompletedProcess(
        ["git", "rev-parse"],
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    clean = subprocess.CompletedProcess(["git", "status"], 0, b"", b"")

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
    revision = subprocess.CompletedProcess(
        ["git", "rev-parse"],
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    dirty = subprocess.CompletedProcess(["git", "status"], 0, status_output.encode(), b"")

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
    revision = subprocess.CompletedProcess(
        ["git", "rev-parse"],
        0,
        f"{git_revision}\n".encode(),
        b"",
    )
    clean = subprocess.CompletedProcess(["git", "status"], 0, b"", b"")
    dirty = subprocess.CompletedProcess(
        ["git", "status"],
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
        ignored_root=ignored_root,
        utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
        monotonic_ns=created_monotonic_ns,
    )
    return path, ignored_root, created_monotonic_ns


def _source_inspection() -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "User": "10001:10001",
                "Entrypoint": ["/usr/sbin/chronyd"],
                "Cmd": [
                    "-x",
                    "-d",
                    "-U",
                    "-f",
                    "/etc/autoquant/trusted-time/chrony.conf",
                ],
                "ExposedPorts": None,
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"],
            }
        }
    ]


def _supervisor_inspection() -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "User": "10001:10001",
                "Entrypoint": None,
                "Cmd": ["autoquant-trusted-time-supervisor"],
                "ExposedPorts": None,
                "Env": [
                    "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin",
                    "PYTHONDONTWRITEBYTECODE=1",
                ],
            }
        }
    ]


def test_image_inspections_accept_exact_nonroot_outbound_only_contract() -> None:
    validate_source_inspection(_source_inspection())
    validate_supervisor_inspection(_supervisor_inspection())


@pytest.mark.parametrize(
    ("source", "field_name", "value"),
    [
        (True, "User", "0:0"),
        (True, "Entrypoint", ["/bin/sh"]),
        (True, "Cmd", ["-d"]),
        (True, "ExposedPorts", {"123/udp": {}}),
        (False, "User", "root"),
        (False, "Cmd", ["autoquant-trader"]),
        (False, "ExposedPorts", {"8000/tcp": {}}),
    ],
)
def test_image_inspections_reject_identity_command_or_port_drift(
    source: bool,
    field_name: str,
    value: object,
) -> None:
    inspection = _source_inspection() if source else _supervisor_inspection()
    configuration = cast(dict[str, object], inspection[0]["Config"])
    configuration[field_name] = value

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
    inspection = _supervisor_inspection()
    configuration = cast(dict[str, object], inspection[0]["Config"])
    environment = cast(list[str], configuration["Env"])
    environment.append(environment_entry)

    with pytest.raises(TrustedTimeImageVerificationError, match="secret"):
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


def test_pinned_database_ca_requires_exact_root_owned_read_only_metadata() -> None:
    validate_database_ca_metadata(0, "0:0:444\n", "")

    for output in ("10001:0:444\n", "0:0:644\n", "0:0:444"):
        with pytest.raises(TrustedTimeImageVerificationError, match="metadata drifted"):
            validate_database_ca_metadata(0, output, "")


def test_supervisor_schema_probe_requires_exact_0036_head_and_anchor_relations() -> None:
    assert SUPERVISOR_APPLICATION_PYTHON == "/opt/venv/bin/python"
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

    validate_secretless_supervisor(2, json.dumps(payload), "")

    payload["readiness_authorized"] = True
    with pytest.raises(TrustedTimeImageVerificationError, match="blocked contract"):
        validate_secretless_supervisor(2, json.dumps(payload), "")
    with pytest.raises(TrustedTimeImageVerificationError, match="quietly"):
        validate_secretless_supervisor(2, "{}", "secret detail")


def test_image_identity_resolution_requires_one_exact_sha256_id() -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "image", "inspect"],
        0,
        f"{SOURCE_ID}\n",
        "",
    )
    with patch("scripts.verify_trusted_time_images._docker", return_value=completed):
        assert resolve_image_id(SOURCE_IMAGE) == SOURCE_ID

    malformed = subprocess.CompletedProcess(
        ["docker", "image", "inspect"],
        0,
        f"{SOURCE_ID}\n{SUPERVISOR_ID}\n",
        "",
    )
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
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(cast(dict[str, str], kwargs["environment"]))
        assert kwargs["maximum_stdout_bytes"] == 4 * 1_024 * 1_024
        assert kwargs["maximum_stderr_bytes"] == 1 * 1_024 * 1_024
        assert kwargs["maximum_stdin_bytes"] == 0
        return subprocess.CompletedProcess(argv, 0, f"{SOURCE_ID}\n".encode(), b"")

    with patch(
        "scripts.verify_trusted_time_images.run_bounded_subprocess",
        side_effect=fake_run,
    ):
        assert resolve_image_id(SOURCE_ID, environment=exact_environment) == SOURCE_ID

    assert observed == [exact_environment]
    assert "DOCKER_CONTEXT" not in observed[0]


def test_read_only_image_probe_never_pulls() -> None:
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")

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
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")

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
        identities = verify_images(
            SOURCE_ID,
            SUPERVISOR_ID,
            docker_environment=exact_environment,
        )

    assert identities == TrustedTimeImageIdentities(
        source_id=SOURCE_ID,
        supervisor_id=SUPERVISOR_ID,
    )
    for helper in (resolve, inspect, run_read_only, docker, probe):
        assert helper.call_count > 0
        assert all(
            call.kwargs["environment"] == exact_environment for call in helper.call_args_list
        )
    assert all(
        call.kwargs["environment"] == exact_environment for call in run_read_only.call_args_list
    )
    assert all(
        "--pull=never" in call.args for call in docker.call_args_list if call.args[0] == "run"
    )


def test_build_uses_one_sealed_context_and_exact_secretless_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AQT_TRUSTED_TIME_DATABASE_URL", "must-not-be-forwarded")
    exact_environment = {"PATH": "/fixed/docker/path"}
    context = b"sealed-head-context"
    source_completed = subprocess.CompletedProcess(
        ["docker", "build"],
        0,
        f"{SOURCE_ID}\n",
        "",
    )
    supervisor_completed = subprocess.CompletedProcess(
        ["docker", "build"],
        0,
        f"{SUPERVISOR_ID}\n",
        "",
    )

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
        subprocess.CompletedProcess(["docker", "build"], 0, "", ""),
        subprocess.CompletedProcess(["docker", "build"], 0, "mutable:tag\n", ""),
        subprocess.CompletedProcess(
            ["docker", "build"],
            0,
            f"{SOURCE_ID}\n{SOURCE_ID}\n",
            "",
        ),
        subprocess.CompletedProcess(["docker", "build"], 0, f"{SOURCE_ID}\n", "warning"),
    ],
)
def test_build_rejects_nonexact_immutable_identity_output(
    completed: subprocess.CompletedProcess[str],
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

    def verified_images(*images: str, **_: object) -> TrustedTimeImageIdentities:
        assert images == (SOURCE_ID, SUPERVISOR_ID)
        events.append("images-verified")
        return identities

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
            "scripts.verify_trusted_time_images.verify_images",
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
            "scripts.verify_trusted_time_images.verify_images",
            return_value=drifted,
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


def test_existing_image_readmission_reverifies_exact_ids_without_building(
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
            "scripts.verify_trusted_time_images.verify_images",
            return_value=identities,
        ) as verify,
        patch(
            "scripts.verify_trusted_time_images.write_image_admission_artifact",
            return_value=retained,
        ) as write,
        patch("scripts.verify_trusted_time_images.build_trusted_time_images") as build,
    ):
        result = verify_and_write_existing_image_admission(
            artifact_path,
            SOURCE_ID,
            SUPERVISOR_ID,
            ignored_root=ignored_root,
        )

    assert result is retained
    build.assert_not_called()
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
            "scripts.verify_trusted_time_images.verify_images",
            return_value=identities,
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
            "scripts.verify_trusted_time_images.verify_images",
            return_value=drifted,
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
        reviewed_input_bindings().source_revision_sha256
    )
    assert payload["inputs"]["schema_revision"] == "0036_phase6_time_anchors"
    assert payload["contract_version"] == "phase6d-trusted-time-image-admission-v2"
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
    real_fstat = os.fstat
    target_observations = 0

    def drifting_fstat(descriptor: int) -> object:
        nonlocal target_observations
        observed = real_fstat(descriptor)
        if (
            stat.S_ISREG(observed.st_mode)
            and (
                observed.st_dev,
                observed.st_ino,
            )
            == target_identity
        ):
            target_observations += 1
            if target_observations == 2:
                values = {
                    "st_dev": observed.st_dev,
                    "st_ino": observed.st_ino,
                    "st_mode": observed.st_mode,
                    "st_uid": observed.st_uid,
                    "st_nlink": observed.st_nlink,
                    "st_size": observed.st_size,
                    "st_mtime_ns": observed.st_mtime_ns,
                    "st_ctime_ns": observed.st_ctime_ns,
                }
                values[drift_field] = {
                    "st_mode": stat.S_IFREG | 0o640,
                    "st_uid": observed.st_uid + 1,
                    "st_nlink": observed.st_nlink + 1,
                    "st_ctime_ns": observed.st_ctime_ns + 1,
                }[drift_field]
                return SimpleNamespace(**values)
        return observed

    message = "changed during read" if target_kind == "canonical" else "archive is invalid"
    with (
        patch("scripts.verify_trusted_time_images.os.fstat", side_effect=drifting_fstat),
        pytest.raises(TrustedTimeImageVerificationError, match=message),
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

    with pytest.raises(TrustedTimeImageVerificationError, match="archive is invalid"):
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
    with pytest.raises(TrustedTimeImageVerificationError, match="malformed"):
        load_image_admission_artifact(
            path,
            ignored_root=ignored_root,
            monotonic_ns=created + 1,
        )

    _write_admission(tmp_path)
    path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    path.chmod(0o600)
    with pytest.raises(TrustedTimeImageVerificationError, match="not canonical"):
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
    with pytest.raises(TrustedTimeImageVerificationError, match="metadata"):
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
            bindings=bindings,
            ignored_root=ignored_root,
            utc_now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
            monotonic_ns=1,
        )

    path.unlink()
    changed = replace(bindings, source_revision_sha256="0" * 64)
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

    def result(arguments: tuple[str, ...], stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["docker", *arguments], 0, stdout, "")

    def fake_docker(*arguments: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        observed_environments.append(kwargs.get("environment"))
        if arguments[:2] == ("volume", "create"):
            return result(arguments, f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
                ),
            )
        if arguments[:2] == ("run", "--detach"):
            return result(arguments, "3" * 64 + "\n")
        if arguments[:2] == ("container", "inspect"):
            inspection = [
                {
                    "Image": SOURCE_ID,
                    "Config": {"User": "10001:10001"},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges"],
                        "Binds": None,
                        "Tmpfs": {
                            "/tmp": (
                                "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"
                            ),
                            "/var/lib/chrony": (
                                "rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"
                            ),
                        },
                        "Mounts": [
                            {
                                "Type": "volume",
                                "Source": volume_name,
                                "Target": "/run/chrony",
                                "VolumeOptions": {"NoCopy": True},
                            }
                        ],
                    },
                    "Mounts": [
                        {
                            "Type": "volume",
                            "Name": volume_name,
                            "Destination": "/run/chrony",
                            "RW": True,
                        }
                    ],
                }
            ]
            return result(arguments, json.dumps(inspection))
        if arguments[:2] == ("container", "exec") and "/bin/stat" in arguments:
            return result(arguments, "10001:10001:750\n")
        if arguments[:2] == ("container", "exec"):
            return result(arguments, "200 OK\n")
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
    supervisor_run = next(call for call in calls if call[:2] == ("run", "--rm"))
    assert "--pull=never" in source_run
    assert "--pull=never" in supervisor_run
    assert "none" in source_run and "--read-only" in source_run and "ALL" in source_run
    assert SOURCE_ID in source_run and SUPERVISOR_ID in supervisor_run
    assert any(volume_name in argument for argument in source_run)
    assert any(volume_name in argument for argument in supervisor_run)
    assert calls[-2:] == [
        ("container", "rm", "--force", source_name),
        ("volume", "rm", volume_name),
    ]
    assert observed_environments
    assert all(environment == exact_environment for environment in observed_environments)


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
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", *arguments],
            returncode,
            stdout,
            stderr,
        )

    def fake_docker(*arguments: str, **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
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
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", *arguments],
            returncode,
            stdout,
            stderr,
        )

    def fake_docker(*arguments: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed_environments.append(kwargs.get("environment"))
        if arguments[:2] == ("volume", "create"):
            return result(arguments, stdout=f"{volume_name}\n")
        if arguments[:2] == ("volume", "inspect"):
            return result(
                arguments,
                stdout=json.dumps(
                    [
                        {
                            "Name": volume_name,
                            "Driver": "local",
                            "Options": {
                                "type": "tmpfs",
                                "device": "tmpfs",
                                "o": "size=8m,uid=10001,gid=10001,mode=0750",
                            },
                        }
                    ]
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
