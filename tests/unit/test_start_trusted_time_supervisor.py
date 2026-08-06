from __future__ import annotations

import hashlib
import json
import os
import selectors
import stat
import subprocess
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
    DATABASE_SECRET_ROOT,
    DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
    HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_AUTHORITY_FILE_NAME,
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES,
    MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES,
    UNENROLLED_ADMISSION_CONTRACT_VERSION,
    LocalDockerDaemonIdentity,
    MaterializedDatabaseSecret,
    MaterializedHeadAnchorFile,
    MaterializedHeadAnchorInputs,
    SupervisorTerminalEvidence,
    TrustedTimeHeadAnchorSourcePayloads,
    TrustedTimeSupervisorAdmissionOutputError,
    TrustedTimeSupervisorAdmissionRetentionUnconfirmed,
    TrustedTimeSupervisorSecureLaunchIncomplete,
    TrustedTimeSupervisorTerminalNotObserved,
    TrustedTimeSupervisorTerminalObserved,
    TrustedTimeSupervisorTerminalUnqualified,
    TrustedTimeVolumeIdentities,
    _approved_database_secret_source_path,
    _capture_trusted_time_volume_identities,
    _compose_container_id,
    _emit_unenrolled_admission_receipt,
    _inspect_supervisor_narrow_state,
    _read_supervisor_terminal_evidence,
    _run_docker_bounded,
    _TrustedTimeSupervisorContainerIdentityUnavailable,
    _validate_chrony_state_directory,
    _validate_mounted_database_secret,
    _validate_unenrolled_admission_teardown,
    build_unenrolled_admission_receipt,
    cleanup_materialized_database_secret,
    cleanup_materialized_trusted_time_head_anchor_inputs,
    compose_argv,
    load_runtime_database_url,
    load_trusted_time_head_anchor_source_payloads,
    main,
    materialize_database_secret,
    materialize_trusted_time_head_anchor_inputs,
    observe_unenrolled_supervisor_terminal,
    qualify_local_docker_daemon,
    run_local_topology,
    validate_chrony_state_volume_inspection,
    validate_created_container,
    validate_materialized_database_secret,
    validate_materialized_trusted_time_head_anchor_inputs,
    write_unenrolled_admission_receipt,
)
from scripts.verify_trusted_time_images import (
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    TrustedTimeImageAdmission,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
)

DATABASE_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:secret"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
SOURCE_CONTAINER_ID = "a" * 64
SUPERVISOR_CONTAINER_ID = "b" * 64
DAEMON_IDENTITY = LocalDockerDaemonIdentity(
    context_name="desktop-linux",
    endpoint="unix:///local/docker.sock",
    daemon_id="LOCAL:DAEMON:1",
)
VOLUME_IDENTITIES = TrustedTimeVolumeIdentities(
    socket_sha256="5" * 64,
    state_sha256="6" * 64,
)
HEAD_ANCHOR_AUTHORITY = b'{"authority":"launcher-test"}\n'
HEAD_ANCHOR_AUTH_SECRET = b'{"password":"not-a-real-secret"}\n'
HEAD_ANCHOR_SIGNING_KEY = b"k" * 32
EXPECTED_TERMINAL_REASON = "head_anchor_remote_history_absent_enrollment_not_approved"
ADMISSION_ID = "123e4567-e89b-42d3-a456-426614174000"
SUPERVISOR_AUTHORITY_FIELDS = {
    "alert_delivery_authorized",
    "arming_authorized",
    "automatic_rearm_authorized",
    "automatic_resume_authorized",
    "broker_action_authorized",
    "exposure_authorized",
    "live_trading_authorized",
    "new_exposure_authorized",
    "operational_control_authorized",
    "paper_trading_authorized",
    "readiness_authorized",
    "rearm_authorized",
}


def _supervisor_terminal_line(
    *,
    reason: str = "supervision_failed",
    extra: dict[str, object] | None = None,
) -> str:
    payload: dict[str, object] = {
        **{field_name: False for field_name in SUPERVISOR_AUTHORITY_FIELDS},
        "reason": reason,
        "service": "trusted-time-supervisor",
        "status": "fatal",
    }
    if extra is not None:
        payload.update(extra)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _supervisor_state_line(
    *,
    status: str = "exited",
    running: bool = False,
    exit_code: int = 2,
    oom_killed: bool = False,
    image_id: str = SUPERVISOR_IMAGE_ID,
    project: str = "autoquanttrader-trusted-time",
    service: str = "trusted-time-supervisor",
    container_id: str = SUPERVISOR_CONTAINER_ID,
    restart_count: int = 0,
    dead: bool = False,
    state_error: str = "",
) -> str:
    values = (
        container_id,
        image_id,
        project,
        service,
        restart_count,
        status,
        running,
        exit_code,
        oom_killed,
        dead,
        state_error,
    )
    return "\t".join(json.dumps(value) for value in values) + "\n"


def _admitted_receipt(*, admission_id: str = ADMISSION_ID) -> bytes:
    return build_unenrolled_admission_receipt(
        admission_id=admission_id,
        image_admission_sha256="4" * 64,
        terminal_evidence=SupervisorTerminalEvidence(
            state="exited",
            exit_code=2,
            status="fatal",
            reason=EXPECTED_TERMINAL_REASON,
        ),
    )


def _admission() -> TrustedTimeImageAdmission:
    return TrustedTimeImageAdmission(
        path=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        identities=TrustedTimeImageIdentities(
            source_id=SOURCE_IMAGE_ID,
            supervisor_id=SUPERVISOR_IMAGE_ID,
        ),
        source_revision_sha256="3" * 64,
        artifact_sha256="4" * 64,
        created_at_utc="2026-07-31T18:00:00.000000Z",
        created_monotonic_ns=1,
    )


def _materialized_secret() -> MaterializedDatabaseSecret:
    directory = DATABASE_SECRET_ROOT / (".database-secret-" + "a" * 32)
    return MaterializedDatabaseSecret(
        root=DATABASE_SECRET_ROOT,
        ignored_root=DATABASE_SECRET_ROOT.parents[1],
        directory=directory,
        path=directory / "database-url",
        directory_device=1,
        directory_inode=2,
        file_device=1,
        file_inode=3,
        size=len(DATABASE_URL.encode()),
        sha256="5" * 64,
    )


def _materialized_head_anchor_file(
    *,
    kind: str,
    file_name: str,
    size: int,
    digest: str,
) -> MaterializedHeadAnchorFile:
    directory = DATABASE_SECRET_ROOT / f".head-anchor-{kind}-{'a' * 32}"
    return MaterializedHeadAnchorFile(
        root=DATABASE_SECRET_ROOT,
        ignored_root=DATABASE_SECRET_ROOT.parents[1],
        directory=directory,
        path=directory / file_name,
        directory_device=1,
        directory_inode={"authority": 11, "auth": 12, "signing-key": 13}[kind],
        file_device=1,
        file_inode={"authority": 21, "auth": 22, "signing-key": 23}[kind],
        size=size,
        sha256=digest,
        kind=kind,
    )


def _head_anchor_payloads() -> TrustedTimeHeadAnchorSourcePayloads:
    return TrustedTimeHeadAnchorSourcePayloads(
        authority=HEAD_ANCHOR_AUTHORITY,
        auth_secret=HEAD_ANCHOR_AUTH_SECRET,
        signing_key=HEAD_ANCHOR_SIGNING_KEY,
    )


def _materialized_head_anchor_inputs() -> MaterializedHeadAnchorInputs:
    return MaterializedHeadAnchorInputs(
        authority=_materialized_head_anchor_file(
            kind="authority",
            file_name=HEAD_ANCHOR_AUTHORITY_FILE_NAME,
            size=len(HEAD_ANCHOR_AUTHORITY),
            digest="6" * 64,
        ),
        auth_secret=_materialized_head_anchor_file(
            kind="auth",
            file_name=HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
            size=len(HEAD_ANCHOR_AUTH_SECRET),
            digest="7" * 64,
        ),
        signing_key=_materialized_head_anchor_file(
            kind="signing-key",
            file_name=HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
            size=len(HEAD_ANCHOR_SIGNING_KEY),
            digest="8" * 64,
        ),
    )


def _env_file(tmp_path: Path, payload: str) -> Path:
    path = tmp_path / "runtime.env"
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path


def _head_anchor_source_environment(tmp_path: Path) -> str:
    values = {
        HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT: HEAD_ANCHOR_AUTHORITY,
        HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT: HEAD_ANCHOR_AUTH_SECRET,
        HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT: HEAD_ANCHOR_SIGNING_KEY,
    }
    lines: list[str] = []
    for variable, payload in values.items():
        path = tmp_path / f"{variable.lower()}.bin"
        path.write_bytes(payload)
        path.chmod(0o600)
        lines.append(f"{variable}={path}")
    return "\n".join(lines) + "\n"


def test_owner_only_loader_extracts_only_valid_runtime_database_url(tmp_path: Path) -> None:
    env_file = _env_file(
        tmp_path,
        f"AQT_DATABASE_URL={DATABASE_URL}\nALPACA_PAPER_API_SECRET=not-forwarded\n",
    )

    assert load_runtime_database_url(env_file) == DATABASE_URL


@pytest.mark.parametrize(
    "payload",
    [
        "AQT_LOG_LEVEL=INFO\n",
        f"AQT_DATABASE_URL={DATABASE_URL}\nAQT_DATABASE_URL={DATABASE_URL}\n",
        "AQT_DATABASE_URL=sqlite+pysqlite:///:memory:\n",
    ],
)
def test_owner_env_loader_rejects_missing_duplicate_or_wrong_database(
    tmp_path: Path,
    payload: str,
) -> None:
    env_file = _env_file(tmp_path, payload)

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        load_runtime_database_url(env_file)


def test_owner_env_loader_rejects_broad_permissions(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    env_file.chmod(0o644)

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="env file was rejected"):
        load_runtime_database_url(env_file)


def test_head_anchor_source_loader_reads_only_exact_owner_files(tmp_path: Path) -> None:
    env_file = _env_file(
        tmp_path,
        _head_anchor_source_environment(tmp_path) + "ALPACA_PAPER_API_SECRET=not-forwarded\n",
    )

    assert load_trusted_time_head_anchor_source_payloads(env_file) == _head_anchor_payloads()


@pytest.mark.parametrize("tamper", ["broad-mode", "symlink", "wrong-key-size"])
def test_head_anchor_source_loader_rejects_unsafe_source_files(
    tmp_path: Path,
    tamper: str,
) -> None:
    environment = _head_anchor_source_environment(tmp_path)
    paths = {
        line.partition("=")[0]: Path(line.partition("=")[2]) for line in environment.splitlines()
    }
    if tamper == "broad-mode":
        paths[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT].chmod(0o644)
    elif tamper == "symlink":
        target = paths[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT]
        held = target.with_name("held-authority")
        target.replace(held)
        target.symlink_to(held)
    else:
        paths[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT].write_bytes(b"short")
    env_file = _env_file(tmp_path, environment)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="head-anchor source file was rejected",
    ):
        load_trusted_time_head_anchor_source_payloads(env_file)


def test_head_anchor_inputs_are_separate_owner_only_inodes_and_cleanup_is_complete(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"
    inputs = materialize_trusted_time_head_anchor_inputs(
        _head_anchor_payloads(),
        root=root,
        ignored_root=ignored_root,
    )

    validate_materialized_trusted_time_head_anchor_inputs(inputs)
    expected = (
        (inputs.authority, HEAD_ANCHOR_AUTHORITY),
        (inputs.auth_secret, HEAD_ANCHOR_AUTH_SECRET),
        (inputs.signing_key, HEAD_ANCHOR_SIGNING_KEY),
    )
    assert len({item.file_inode for item, _ in expected}) == 3
    assert len({item.directory_inode for item, _ in expected}) == 3
    for item, payload in expected:
        assert item.path.read_bytes() == payload
        assert stat.S_IMODE(item.path.stat().st_mode) == 0o400
        assert stat.S_IMODE(item.directory.stat().st_mode) == 0o700
        assert item.path.stat().st_nlink == 1
    cleanup_materialized_trusted_time_head_anchor_inputs(inputs)
    for item, _ in expected:
        assert not os.path.lexists(item.path)
        assert not os.path.lexists(item.directory)


def test_database_secret_is_exact_owner_only_inode_and_cleanup_is_complete(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"

    secret = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )

    validate_materialized_database_secret(secret)
    assert secret.path.read_bytes() == DATABASE_URL.encode()
    assert stat.S_IMODE(secret.path.stat().st_mode) == 0o400
    assert stat.S_IMODE(secret.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert secret.path.stat().st_nlink == 1
    cleanup_materialized_database_secret(secret)
    assert not os.path.lexists(secret.path)
    assert not os.path.lexists(secret.directory)


def test_database_secret_recheck_rejects_mode_tamper_and_symlink_swap(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"
    secret = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )
    secret.path.chmod(0o600)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="metadata changed"):
        validate_materialized_database_secret(secret)
    secret.path.chmod(0o400)
    cleanup_materialized_database_secret(secret)

    replaced = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )
    held = replaced.directory / "held"
    replaced.path.replace(held)
    replaced.path.symlink_to(held)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="metadata changed"):
        validate_materialized_database_secret(replaced)
    replaced.path.unlink()
    held.replace(replaced.path)
    cleanup_materialized_database_secret(replaced)


def test_inspector_secret_source_pattern_requires_completed_host_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source = root / (".database-secret-" + "a" * 32) / "database-url"
    monkeypatch.setattr(
        "scripts.start_trusted_time_supervisor.DATABASE_SECRET_ROOT",
        root,
    )

    assert _approved_database_secret_source_path(str(source))
    assert _approved_database_secret_source_path("/host_mnt" + str(source))
    assert not _approved_database_secret_source_path("/host_mnt/host_mnt" + str(source))
    source.parent.mkdir(parents=True)
    assert not _approved_database_secret_source_path(str(source))
    assert not _approved_database_secret_source_path("/host_mnt" + str(source))
    source.write_text("lookalike", encoding="utf-8")
    assert not _approved_database_secret_source_path(str(source))


def test_retired_mounted_secret_accepts_only_exact_digest_or_failed_read() -> None:
    expected_sha256 = "a" * 64
    metadata = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        0,
        "10001:10001:400:137\n",
        "",
    )
    retired = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        1,
        "",
        "sha256sum: cannot open retired mount\n",
    )
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker",
        side_effect=[metadata, retired],
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
            allow_retired_unreadable=True,
        )

    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=[metadata, retired],
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="differs"),
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
        )

    changed = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        0,
        "b" * 64 + "  /run/secrets/trusted_time_database_url\n",
        "",
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=[metadata, changed],
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="differs"),
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
            allow_retired_unreadable=True,
        )


@pytest.mark.parametrize(
    "reason",
    ["configuration_rejected", "supervision_failed", EXPECTED_TERMINAL_REASON],
)
def test_supervisor_terminal_parser_accepts_only_closed_canonical_fatal_line(
    reason: str,
) -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "container", "logs"],
        0,
        _supervisor_terminal_line(reason=reason),
        "",
    )
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker_bounded",
        return_value=completed,
    ) as run:
        evidence = _read_supervisor_terminal_evidence(
            SUPERVISOR_CONTAINER_ID,
            environment={"PATH": "/usr/bin", "AQT_DATABASE_URL": "must-not-pass"},
        )

    assert evidence == SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=reason,
    )
    assert run.call_args.kwargs["maximum_stdout_bytes"] == (MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES)
    if reason != EXPECTED_TERMINAL_REASON:
        with pytest.raises(TrustedTimeSupervisorConfigurationError):
            TrustedTimeSupervisorTerminalObserved(
                evidence,
                image_admission_sha256="4" * 64,
            )


def test_unenrolled_admission_receipt_is_closed_canonical_and_non_authorizing() -> None:
    encoded = _admitted_receipt()

    assert len(encoded) <= MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    payload = json.loads(encoded)
    assert payload == {
        "admission_id": ADMISSION_ID,
        "authority_granted": False,
        "contract_version": UNENROLLED_ADMISSION_CONTRACT_VERSION,
        "database_secret_disclosed": False,
        "gates": {
            "runtime_inputs_retired": True,
            "secure_launch_validated": True,
            "state_volumes_preserved": True,
            "topology_removed": True,
        },
        "image_admission_sha256": "4" * 64,
        "new_exposure_authorized": False,
        "reason": "expected_unenrolled_fail_closed_observed",
        "service": "trusted-time-local-launcher",
        "status": "admitted",
        "supervisor": {
            "authorities_all_false": True,
            "exit_code": 2,
            "oom_killed": False,
            "reason": EXPECTED_TERMINAL_REASON,
            "state": "exited",
            "status": "fatal",
        },
    }
    assert encoded == (
        json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


@pytest.mark.parametrize(
    "admission_id",
    [
        "123e4567-e89b-12d3-a456-426614174000",
        "123E4567-E89B-42D3-A456-426614174000",
        "not-a-uuid",
        "",
    ],
)
def test_unenrolled_admission_receipt_rejects_noncanonical_uuid4(
    admission_id: str,
) -> None:
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        _admitted_receipt(admission_id=admission_id)


def test_unenrolled_admission_receipt_rejects_unexpected_terminal_and_digest() -> None:
    unexpected = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason="supervision_failed",
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        build_unenrolled_admission_receipt(
            admission_id=ADMISSION_ID,
            image_admission_sha256="4" * 64,
            terminal_evidence=unexpected,
        )
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        build_unenrolled_admission_receipt(
            admission_id=ADMISSION_ID,
            image_admission_sha256="secret-canary",
            terminal_evidence=SupervisorTerminalEvidence(
                state="exited",
                exit_code=2,
                status="fatal",
                reason=EXPECTED_TERMINAL_REASON,
            ),
        )


def test_unenrolled_admission_artifact_is_owner_only_content_addressed(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time" / "admissions"
    encoded = _admitted_receipt()

    artifact = write_unenrolled_admission_receipt(
        artifact_dir,
        encoded,
        ignored_root=ignored_root,
    )

    digest = hashlib.sha256(encoded).hexdigest()
    assert artifact == (artifact_dir / f"trusted-time-unenrolled-launch-admission-{digest}.json")
    assert artifact.read_bytes() == encoded
    metadata = artifact.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    for directory in (ignored_root, ignored_root / "trusted-time", artifact_dir):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert list(artifact_dir.iterdir()) == [artifact]


def test_unenrolled_admission_artifact_rejects_metadata_drift_during_reread(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    encoded = _admitted_receipt()
    digest = hashlib.sha256(encoded).hexdigest()
    artifact = artifact_dir / f"trusted-time-unenrolled-launch-admission-{digest}.json"
    real_read = os.read
    drifted = False

    def drifting_read(descriptor: int, size: int) -> bytes:
        nonlocal drifted
        chunk = real_read(descriptor, size)
        if not chunk and not drifted:
            artifact.chmod(0o640)
            drifted = True
        return chunk

    with (
        patch("scripts.start_trusted_time_supervisor.os.read", side_effect=drifting_read),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="write failed"),
    ):
        write_unenrolled_admission_receipt(
            artifact_dir,
            encoded,
            ignored_root=ignored_root,
        )

    assert drifted is True
    assert not artifact.exists()
    assert not any(path.name.endswith(".tmp") for path in artifact_dir.iterdir())


def test_unenrolled_admission_artifact_success_is_not_cancelled_by_final_close_error(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    artifact_dir.mkdir(parents=True, mode=0o700)
    ignored_root.chmod(0o700)
    artifact_dir.chmod(0o700)
    encoded = _admitted_receipt()
    directory_descriptor = os.open(artifact_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    real_close = os.close
    close_failed = False

    def fail_directory_close(descriptor: int) -> None:
        nonlocal close_failed
        if descriptor == directory_descriptor:
            close_failed = True
            raise OSError
        real_close(descriptor)

    try:
        with (
            patch(
                "scripts.start_trusted_time_supervisor._open_owner_only_artifact_directory",
                return_value=directory_descriptor,
            ),
            patch(
                "scripts.start_trusted_time_supervisor.os.close",
                side_effect=fail_directory_close,
            ),
        ):
            artifact = write_unenrolled_admission_receipt(
                artifact_dir,
                encoded,
                ignored_root=ignored_root,
            )
    finally:
        real_close(directory_descriptor)

    assert close_failed is True
    assert artifact.read_bytes() == encoded


def test_unenrolled_admission_artifact_reports_unconfirmed_output_rollback(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    encoded = _admitted_receipt()
    digest = hashlib.sha256(encoded).hexdigest()
    file_name = f"trusted-time-unenrolled-launch-admission-{digest}.json"
    real_unlink = os.unlink

    def fail_final_unlink(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if path == file_name:
            raise OSError
        real_unlink(path, dir_fd=dir_fd)

    with (
        patch(
            "scripts.start_trusted_time_supervisor.os.unlink",
            side_effect=fail_final_unlink,
        ),
        pytest.raises(TrustedTimeSupervisorAdmissionRetentionUnconfirmed),
    ):
        write_unenrolled_admission_receipt(
            artifact_dir,
            encoded,
            ignored_root=ignored_root,
            emit=lambda _: (_ for _ in ()).throw(
                TrustedTimeSupervisorAdmissionOutputError("secret-canary")
            ),
        )

    assert (artifact_dir / file_name).read_bytes() == encoded
    assert not any(path.name.endswith(".tmp") for path in artifact_dir.iterdir())


def test_unenrolled_admission_artifact_refuses_existing_exact_target(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    encoded = _admitted_receipt()
    artifact = write_unenrolled_admission_receipt(
        artifact_dir,
        encoded,
        ignored_root=ignored_root,
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="already exists",
    ):
        write_unenrolled_admission_receipt(
            artifact_dir,
            encoded,
            ignored_root=ignored_root,
        )

    assert artifact.read_bytes() == encoded
    assert list(artifact_dir.iterdir()) == [artifact]


def test_unenrolled_admission_artifact_never_replaces_preexisting_hardlink(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    artifact_dir.mkdir(parents=True, mode=0o700)
    ignored_root.chmod(0o700)
    artifact_dir.chmod(0o700)
    encoded = _admitted_receipt()
    digest = hashlib.sha256(encoded).hexdigest()
    target = artifact_dir / f"trusted-time-unenrolled-launch-admission-{digest}.json"
    canary = tmp_path / "secret-canary"
    canary.write_bytes(b"must-not-replace")
    os.link(canary, target)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="already exists",
    ) as captured:
        write_unenrolled_admission_receipt(
            artifact_dir,
            encoded,
            ignored_root=ignored_root,
        )

    assert "must-not-replace" not in str(captured.value)
    assert target.read_bytes() == b"must-not-replace"
    assert target.stat().st_ino == canary.stat().st_ino
    assert not any(path.name.endswith(".tmp") for path in artifact_dir.iterdir())


def test_unenrolled_admission_artifact_rejects_paths_and_directory_drift(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    encoded = _admitted_receipt()
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="path is invalid"):
        write_unenrolled_admission_receipt(
            Path("artifacts/trusted-time"),
            encoded,
            ignored_root=ignored_root,
        )
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="path is invalid"):
        write_unenrolled_admission_receipt(
            tmp_path / "outside",
            encoded,
            ignored_root=ignored_root,
        )

    drifted = ignored_root / "trusted-time" / "drifted"
    drifted.mkdir(parents=True)
    drifted.chmod(0o755)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="write failed"):
        write_unenrolled_admission_receipt(
            drifted,
            encoded,
            ignored_root=ignored_root,
        )

    target = ignored_root / "trusted-time" / "real"
    target.mkdir(mode=0o700)
    symlink = ignored_root / "trusted-time" / "symlink"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="write failed"):
        write_unenrolled_admission_receipt(
            symlink,
            encoded,
            ignored_root=ignored_root,
        )


def test_unenrolled_admission_artifact_rejects_secret_canary_and_oversize(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_dir = ignored_root / "trusted-time"
    payload = json.loads(_admitted_receipt())
    payload["secret-canary"] = "must-not-retain"
    canary = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        write_unenrolled_admission_receipt(
            artifact_dir,
            canary,
            ignored_root=ignored_root,
        )
    assert "secret-canary" not in str(captured.value)
    assert not artifact_dir.exists()

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        write_unenrolled_admission_receipt(
            artifact_dir,
            b"x" * (MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES + 1),
            ignored_root=ignored_root,
        )
    assert not artifact_dir.exists()


def test_unenrolled_admission_uuid_changes_content_address() -> None:
    first = _admitted_receipt(admission_id="123e4567-e89b-42d3-a456-426614174000")
    second = _admitted_receipt(admission_id="123e4567-e89b-42d3-b456-426614174001")

    assert first != second
    assert hashlib.sha256(first).digest() != hashlib.sha256(second).digest()


def _volume_inspection(
    name: str,
    *,
    created_at: str,
    socket: bool,
) -> list[dict[str, object]]:
    return [
        {
            "CreatedAt": created_at,
            "Driver": "local",
            "Labels": {
                "com.docker.compose.project": "autoquanttrader-trusted-time",
                "com.docker.compose.volume": (
                    "chrony_command_socket" if socket else "chrony_state"
                ),
            },
            "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
            "Name": name,
            "Options": (
                {
                    "device": "tmpfs",
                    "o": "size=8m,uid=10001,gid=10001,mode=0750",
                    "type": "tmpfs",
                }
                if socket
                else None
            ),
            "Scope": "local",
        }
    ]


def test_volume_identity_capture_binds_creation_and_mount_identity() -> None:
    socket = _volume_inspection(
        COMPOSE_SOCKET_VOLUME_NAME,
        created_at="2026-08-05T10:00:00Z",
        socket=True,
    )
    state = _volume_inspection(
        COMPOSE_STATE_VOLUME_NAME,
        created_at="2026-08-05T10:00:01Z",
        socket=False,
    )
    with patch(
        "scripts.start_trusted_time_supervisor._inspect_volume",
        side_effect=(socket, state),
    ):
        original = _capture_trusted_time_volume_identities(environment={})

    replaced_state = _volume_inspection(
        COMPOSE_STATE_VOLUME_NAME,
        created_at="2026-08-05T10:05:00Z",
        socket=False,
    )
    with patch(
        "scripts.start_trusted_time_supervisor._inspect_volume",
        side_effect=(socket, replaced_state),
    ):
        replaced = _capture_trusted_time_volume_identities(environment={})

    assert original.socket_sha256 == replaced.socket_sha256
    assert original.state_sha256 != replaced.state_sha256


def test_unenrolled_admission_teardown_requires_absence_and_preserved_volumes() -> None:
    empty = subprocess.CompletedProcess(["docker", "compose", "ps"], 0, "", "")
    with (
        patch("scripts.start_trusted_time_supervisor._require_same_local_daemon") as daemon,
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            return_value=empty,
        ) as run,
        patch(
            "scripts.start_trusted_time_supervisor._capture_trusted_time_volume_identities",
            return_value=VOLUME_IDENTITIES,
        ) as capture_volumes,
    ):
        _validate_unenrolled_admission_teardown(
            compose_environment={"PATH": "/usr/bin"},
            docker_environment={"PATH": "/usr/bin"},
            daemon_identity=DAEMON_IDENTITY,
            expected_volume_identities=VOLUME_IDENTITIES,
        )

    assert daemon.call_count == 2
    assert run.call_count == 2
    assert run.call_args_list[1].args[0] == (
        "docker",
        "network",
        "ls",
        "--quiet",
        "--filter",
        f"name=^{COMPOSE_NETWORK_NAME}$",
    )
    capture_volumes.assert_called_once_with(environment={"PATH": "/usr/bin"})


def test_unenrolled_admission_teardown_allows_unbound_early_failure_proof() -> None:
    empty = subprocess.CompletedProcess(["docker", "compose", "ps"], 0, "", "")
    with (
        patch("scripts.start_trusted_time_supervisor._require_same_local_daemon"),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            return_value=empty,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._capture_trusted_time_volume_identities",
            return_value=VOLUME_IDENTITIES,
        ),
    ):
        _validate_unenrolled_admission_teardown(
            compose_environment={"PATH": "/usr/bin"},
            docker_environment={"PATH": "/usr/bin"},
            daemon_identity=DAEMON_IDENTITY,
            expected_volume_identities=None,
        )


def test_unenrolled_admission_teardown_rejects_any_remaining_container() -> None:
    remaining = subprocess.CompletedProcess(
        ["docker", "compose", "ps"],
        0,
        f"{SUPERVISOR_CONTAINER_ID}\n",
        "",
    )
    with (
        patch("scripts.start_trusted_time_supervisor._require_same_local_daemon"),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            return_value=remaining,
        ),
        patch("scripts.start_trusted_time_supervisor._inspect_volume") as inspect_volume,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="removal is unconfirmed"),
    ):
        _validate_unenrolled_admission_teardown(
            compose_environment={"PATH": "/usr/bin"},
            docker_environment={"PATH": "/usr/bin"},
            daemon_identity=DAEMON_IDENTITY,
            expected_volume_identities=VOLUME_IDENTITIES,
        )

    inspect_volume.assert_not_called()


def test_unenrolled_admission_teardown_rejects_remaining_project_network() -> None:
    empty = subprocess.CompletedProcess(["docker", "compose", "ps"], 0, "", "")
    remaining = subprocess.CompletedProcess(
        ["docker", "network", "ls"],
        0,
        "a" * 64 + "\n",
        "",
    )
    with (
        patch("scripts.start_trusted_time_supervisor._require_same_local_daemon"),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            side_effect=(empty, remaining),
        ),
        patch("scripts.start_trusted_time_supervisor._inspect_volume") as inspect_volume,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="network removal"),
    ):
        _validate_unenrolled_admission_teardown(
            compose_environment={"PATH": "/usr/bin"},
            docker_environment={"PATH": "/usr/bin"},
            daemon_identity=DAEMON_IDENTITY,
            expected_volume_identities=VOLUME_IDENTITIES,
        )

    inspect_volume.assert_not_called()


def test_unenrolled_admission_teardown_rejects_replaced_named_volume() -> None:
    empty = subprocess.CompletedProcess(["docker", "compose", "ps"], 0, "", "")
    replaced = TrustedTimeVolumeIdentities(
        socket_sha256=VOLUME_IDENTITIES.socket_sha256,
        state_sha256="7" * 64,
    )
    with (
        patch("scripts.start_trusted_time_supervisor._require_same_local_daemon"),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            return_value=empty,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._capture_trusted_time_volume_identities",
            return_value=replaced,
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="volume preservation"),
    ):
        _validate_unenrolled_admission_teardown(
            compose_environment={"PATH": "/usr/bin"},
            docker_environment={"PATH": "/usr/bin"},
            daemon_identity=DAEMON_IDENTITY,
            expected_volume_identities=VOLUME_IDENTITIES,
        )


def test_compose_container_identity_requires_full_id() -> None:
    short = subprocess.CompletedProcess(
        ["docker", "compose", "ps"],
        0,
        "a" * 12 + "\n",
        "",
    )
    with (
        patch("scripts.start_trusted_time_supervisor._run_docker", return_value=short),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity is unavailable"),
    ):
        _compose_container_id("chrony-nts", environment={})


@pytest.mark.parametrize(
    "stdout,stderr",
    [
        (_supervisor_terminal_line(extra={"secret-sentinel": "do-not-echo"}), ""),
        (_supervisor_terminal_line(extra={"reason": []}), ""),
        (_supervisor_terminal_line(extra={"reason": {}}), ""),
        (_supervisor_terminal_line().replace("\n", "\n{}\n"), ""),
        (_supervisor_terminal_line().replace('"reason":', '"reason":"duplicate","reason":'), ""),
        (json.dumps(json.loads(_supervisor_terminal_line())) + "\n", ""),
        ("x" * MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES + "\n", ""),
        (_supervisor_terminal_line(), "secret-sentinel-on-stderr"),
    ],
)
def test_supervisor_terminal_parser_rejects_untrusted_text_without_echo(
    stdout: str,
    stderr: str,
) -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "container", "logs"],
        0,
        stdout,
        stderr,
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            return_value=completed,
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError) as captured,
    ):
        _read_supervisor_terminal_evidence(SUPERVISOR_CONTAINER_ID, environment={})

    assert "secret-sentinel" not in str(captured.value)
    assert "secret-sentinel" not in repr(captured.value)


def test_supervisor_terminal_evidence_rejects_unhashable_reason() -> None:
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        SupervisorTerminalEvidence(
            state="exited",
            exit_code=2,
            status="fatal",
            reason=cast(str, []),
        )


@pytest.mark.parametrize(
    "state_line,qualified",
    [
        (_supervisor_state_line(status="running", running=True, exit_code=0), True),
        (_supervisor_state_line(), True),
        (_supervisor_state_line(project="secret-sentinel"), False),
        (_supervisor_state_line(service="other"), False),
        (_supervisor_state_line(container_id="c" * 64), False),
        (_supervisor_state_line(restart_count=1), False),
        (_supervisor_state_line(oom_killed=True), False),
        (_supervisor_state_line(dead=True), False),
        (_supervisor_state_line(state_error="secret-sentinel"), False),
        (_supervisor_state_line(exit_code=1), False),
    ],
)
def test_supervisor_narrow_state_is_identity_bound_and_secret_safe(
    state_line: str,
    qualified: bool,
) -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "container", "inspect"],
        0,
        state_line,
        "",
    )
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker_bounded",
        return_value=completed,
    ):
        if qualified:
            state = _inspect_supervisor_narrow_state(
                SUPERVISOR_CONTAINER_ID,
                expected_image_id=SUPERVISOR_IMAGE_ID,
                environment={},
            )
            assert state.status in {"running", "exited"}
        else:
            with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
                _inspect_supervisor_narrow_state(
                    SUPERVISOR_CONTAINER_ID,
                    expected_image_id=SUPERVISOR_IMAGE_ID,
                    environment={},
                )
            assert "secret-sentinel" not in str(captured.value)


def test_terminal_observer_times_out_without_logs_and_strips_all_application_env() -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "container", "inspect"],
        0,
        _supervisor_state_line(status="running", running=True, exit_code=0),
        "",
    )
    observed_environments: list[dict[str, str]] = []

    def bounded_run(*_: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed_environments.append(dict(cast(dict[str, str], kwargs["environment"])))
        return completed

    clock = iter((0.0, 0.0, 0.1))
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker_bounded",
        side_effect=bounded_run,
    ) as run:
        evidence = observe_unenrolled_supervisor_terminal(
            expected_image_id=SUPERVISOR_IMAGE_ID,
            environment={
                "PATH": "/usr/bin",
                "LC_ALL": "C",
                "AQT_DATABASE_URL": "secret-sentinel",
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE": "/secret/path",
                "ETRADE_PROD_API_SECRET": "broker-secret",
                "SENTRY_DSN": "telemetry-secret",
            },
            container_id=SUPERVISOR_CONTAINER_ID,
            timeout_seconds=0.1,
            monotonic_clock=lambda: next(clock),
            sleeper=lambda _: None,
        )

    assert evidence is None
    assert run.call_count == 1
    assert observed_environments == [{"PATH": "/usr/bin", "LC_ALL": "C"}]


def test_terminal_observer_never_sleeps_past_deadline_after_running_inspect() -> None:
    completed = subprocess.CompletedProcess(
        ["docker", "container", "inspect"],
        0,
        _supervisor_state_line(status="running", running=True, exit_code=0),
        "",
    )
    clock = iter((0.0, 0.0, 1.0))
    sleeps: list[float] = []
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker_bounded",
        return_value=completed,
    ):
        evidence = observe_unenrolled_supervisor_terminal(
            expected_image_id=SUPERVISOR_IMAGE_ID,
            environment={},
            container_id=SUPERVISOR_CONTAINER_ID,
            timeout_seconds=1,
            monotonic_clock=lambda: next(clock),
            sleeper=sleeps.append,
        )

    assert evidence is None
    assert sleeps == []


def test_terminal_observer_rebinds_same_full_compose_identity_after_log_read() -> None:
    commands: list[tuple[str, ...]] = []
    environments: list[dict[str, str]] = []
    results = iter(
        (
            subprocess.CompletedProcess(
                ["docker", "container", "inspect"],
                0,
                _supervisor_state_line(),
                "",
            ),
            subprocess.CompletedProcess(
                ["docker", "container", "logs"],
                0,
                _supervisor_terminal_line(reason=EXPECTED_TERMINAL_REASON),
                "",
            ),
            subprocess.CompletedProcess(
                ["docker", "compose", "ps"],
                0,
                f"{SUPERVISOR_CONTAINER_ID}\n",
                "",
            ),
        )
    )

    def bounded_run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        environments.append(dict(cast(dict[str, str], kwargs["environment"])))
        return next(results)

    with patch(
        "scripts.start_trusted_time_supervisor._run_docker_bounded",
        side_effect=bounded_run,
    ):
        evidence = observe_unenrolled_supervisor_terminal(
            expected_image_id=SUPERVISOR_IMAGE_ID,
            environment={"PATH": "/usr/bin", "AQT_DATABASE_URL": "secret-sentinel"},
            container_id=SUPERVISOR_CONTAINER_ID,
            timeout_seconds=1,
            monotonic_clock=lambda: 0.0,
            sleeper=lambda _: None,
        )

    assert evidence == SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )
    assert commands[0][-1] == SUPERVISOR_CONTAINER_ID
    assert commands[1][-1] == SUPERVISOR_CONTAINER_ID
    assert commands[2][-1] == "trusted-time-supervisor"
    assert environments[0] == {"PATH": "/usr/bin"}
    assert environments[1] == {"PATH": "/usr/bin"}
    assert environments[2]["AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"] == "/dev/null"
    assert "secret-sentinel" not in repr(environments)


def test_terminal_observer_rejects_compose_identity_rebind_after_log_read() -> None:
    results = iter(
        (
            subprocess.CompletedProcess(
                ["docker", "container", "inspect"],
                0,
                _supervisor_state_line(),
                "",
            ),
            subprocess.CompletedProcess(
                ["docker", "container", "logs"],
                0,
                _supervisor_terminal_line(reason=EXPECTED_TERMINAL_REASON),
                "",
            ),
            subprocess.CompletedProcess(
                ["docker", "compose", "ps"],
                0,
                f"{'c' * 64}\n",
                "",
            ),
        )
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker_bounded",
            side_effect=lambda *_args, **_kwargs: next(results),
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity changed"),
    ):
        observe_unenrolled_supervisor_terminal(
            expected_image_id=SUPERVISOR_IMAGE_ID,
            environment={},
            container_id=SUPERVISOR_CONTAINER_ID,
            timeout_seconds=1,
            monotonic_clock=lambda: 0.0,
            sleeper=lambda _: None,
        )


def test_bounded_observer_rejects_every_nonallowlisted_docker_command() -> None:
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        _run_docker_bounded(
            ("docker", "container", "logs", "--tail", "2", SUPERVISOR_CONTAINER_ID),
            environment={},
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=128,
            timeout_seconds=1,
        )


def test_bounded_observer_waits_and_polls_after_killing_timed_out_process() -> None:
    class FakeStream:
        closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = FakeStream()
            self.stderr = FakeStream()
            self.killed = False
            self.wait_timeouts: list[float] = []
            self.poll_count = 0

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            assert self.killed is True
            self.wait_timeouts.append(timeout)
            return -9

        def poll(self) -> int | None:
            self.poll_count += 1
            return -9 if self.killed else None

    class FakeSelector:
        def __init__(self) -> None:
            self.registered: list[object] = []
            self.closed = False

        def register(self, fileobj: object, _events: int, _data: object) -> None:
            self.registered.append(fileobj)

        def get_map(self) -> dict[int, object]:
            return {index: stream for index, stream in enumerate(self.registered, start=1)}

        def select(self, _timeout: float) -> list[object]:
            return []

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    selector = FakeSelector()
    with (
        patch("scripts.start_trusted_time_supervisor.subprocess.Popen", return_value=process),
        patch(
            "scripts.start_trusted_time_supervisor.selectors.DefaultSelector", return_value=selector
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="unavailable"),
    ):
        _run_docker_bounded(
            ("docker", "container", "logs", "--tail", "1", SUPERVISOR_CONTAINER_ID),
            environment={},
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=128,
            timeout_seconds=1,
        )

    assert process.killed is True
    assert len(process.wait_timeouts) == 1
    assert 0 < process.wait_timeouts[0] <= 0.25
    assert process.poll_count == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True
    assert selector.closed is True


def test_bounded_observer_preserves_reap_reserve_after_stream_eof() -> None:
    class FakeStream:
        closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = FakeStream()
            self.stderr = FakeStream()
            self.killed = False
            self.wait_timeouts: list[float] = []
            self.poll_count = 0

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            self.wait_timeouts.append(timeout)
            if not self.killed:
                raise subprocess.TimeoutExpired(("docker",), timeout)
            return -9

        def poll(self) -> int | None:
            self.poll_count += 1
            return -9 if self.killed else None

    class FakeSelector:
        def __init__(self) -> None:
            self.keys: list[SimpleNamespace] = []
            self.closed = False

        def register(self, fileobj: object, _events: int, data: object) -> None:
            self.keys.append(
                SimpleNamespace(
                    fileobj=fileobj,
                    fd=len(self.keys) + 10,
                    data=data,
                )
            )

        def unregister(self, fileobj: object) -> None:
            self.keys = [key for key in self.keys if key.fileobj is not fileobj]

        def get_map(self) -> dict[int, object]:
            return {key.fd: key for key in self.keys}

        def select(self, _timeout: float) -> list[tuple[SimpleNamespace, int]]:
            return [(key, selectors.EVENT_READ) for key in tuple(self.keys)]

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    selector = FakeSelector()
    with (
        patch("scripts.start_trusted_time_supervisor.subprocess.Popen", return_value=process),
        patch(
            "scripts.start_trusted_time_supervisor.selectors.DefaultSelector",
            return_value=selector,
        ),
        patch("scripts.start_trusted_time_supervisor.os.read", return_value=b""),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="unavailable"),
    ):
        _run_docker_bounded(
            ("docker", "container", "logs", "--tail", "1", SUPERVISOR_CONTAINER_ID),
            environment={},
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=128,
            timeout_seconds=1,
        )

    assert process.killed is True
    assert len(process.wait_timeouts) == 2
    assert 0 < process.wait_timeouts[0] <= 0.75
    assert 0 < process.wait_timeouts[1] <= 0.25
    assert process.poll_count == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True
    assert selector.closed is True


def _image_configuration(service: str) -> dict[str, object]:
    if service == "chrony-nts":
        return {
            "User": "10001:10001",
            "Entrypoint": ["/usr/sbin/chronyd"],
            "Cmd": [
                "-x",
                "-d",
                "-U",
                "-f",
                "/etc/autoquant/trusted-time/chrony.conf",
            ],
            "WorkingDir": "",
            "ExposedPorts": None,
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"],
        }
    return {
        "User": "10001:10001",
        "Entrypoint": None,
        "Cmd": ["autoquant-trusted-time-supervisor"],
        "WorkingDir": "/workspace",
        "ExposedPorts": None,
        "Env": ["PATH=/opt/venv/bin:/usr/local/bin:/usr/bin"],
    }


def _container_inspection(
    *,
    image_id: str,
    service: str,
    healthy: bool,
) -> list[dict[str, object]]:
    image_configuration = _image_configuration(service)
    runtime_environment = list(cast(list[str], image_configuration["Env"]))
    source = service == "chrony-nts"
    if not source:
        runtime_environment.extend(
            [
                "AQT_TRUSTED_TIME_AUTHORITY_PATH=/etc/autoquant/trusted-time/source-authority.json",
                "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH=/etc/autoquant/trusted-time/chrony.conf",
                "AQT_TRUSTED_TIME_DATABASE_URL_FILE=/run/secrets/trusted_time_database_url",
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH=" + HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE="
                + HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE="
                + HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
            ]
        )
    state: dict[str, object] = {"Running": True, "Status": "running"}
    if healthy:
        state["Health"] = {"Status": "healthy"}
    return [
        {
            "Image": image_id,
            "Config": {
                **image_configuration,
                "Env": runtime_environment,
                "Labels": {
                    "com.docker.compose.project": "autoquanttrader-trusted-time",
                    "com.docker.compose.service": service,
                },
                "Healthcheck": (
                    {
                        "Test": [
                            "CMD",
                            "/usr/bin/chronyc",
                            "-h",
                            "/run/chrony/chronyd.sock",
                            "activity",
                        ],
                        "Interval": 2_000_000_000,
                        "Timeout": 1_000_000_000,
                        "StartPeriod": 2_000_000_000,
                        "Retries": 15,
                    }
                    if source
                    else None
                ),
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Privileged": False,
                "PidsLimit": 32 if source else 64,
                "NanoCpus": 250_000_000 if source else 500_000_000,
                "Memory": 67_108_864 if source else 268_435_456,
                "Init": True,
                "NetworkMode": COMPOSE_NETWORK_NAME,
                "PublishAllPorts": False,
                "PortBindings": {},
                "Devices": None,
                "DeviceCgroupRules": None,
                "Tmpfs": {
                    "/tmp": (
                        "rw,noexec,nosuid,nodev,"
                        f"size={'8m' if source else '16m'},"
                        "uid=10001,gid=10001,mode=0700"
                    )
                },
                "RestartPolicy": {
                    "Name": "unless-stopped" if source else "no",
                    "MaximumRetryCount": 0,
                },
                "Binds": ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw"] if source else None),
                "Mounts": [
                    {
                        "Type": "volume",
                        "Source": COMPOSE_SOCKET_VOLUME_NAME,
                        "Target": "/run/chrony",
                        "VolumeOptions": {"NoCopy": True},
                    },
                    *(
                        [
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".database-secret-" + "a" * 32)
                                    / "database-url"
                                ),
                                "Target": "/run/secrets/trusted_time_database_url",
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-authority-" + "a" * 32)
                                    / HEAD_ANCHOR_AUTHORITY_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-auth-" + "a" * 32)
                                    / HEAD_ANCHOR_AUTH_SECRET_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-signing-key-" + "a" * 32)
                                    / HEAD_ANCHOR_SIGNING_KEY_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                        ]
                        if not source
                        else []
                    ),
                ],
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": COMPOSE_SOCKET_VOLUME_NAME,
                    "Destination": "/run/chrony",
                    "RW": True,
                },
                *(
                    [
                        {
                            "Type": "volume",
                            "Name": COMPOSE_STATE_VOLUME_NAME,
                            "Destination": "/var/lib/chrony",
                            "RW": True,
                        }
                    ]
                    if source
                    else [
                        {
                            "Type": "bind",
                            "Destination": "/run/secrets/trusted_time_database_url",
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
                            "RW": False,
                        },
                    ]
                ),
            ],
            "NetworkSettings": {
                "Networks": {
                    COMPOSE_NETWORK_NAME: {},
                }
            },
            "State": state,
        }
    ]


def test_launcher_qualifies_before_secret_and_starts_only_admitted_ids(
    tmp_path: Path,
) -> None:
    env_file = _env_file(
        tmp_path,
        f"AQT_DATABASE_URL={DATABASE_URL}\nALPACA_PAPER_API_SECRET=not-forwarded\n",
    )
    admission = _admission()
    secret = _materialized_secret()
    head_anchor_payloads = _head_anchor_payloads()
    head_anchor_inputs = _materialized_head_anchor_inputs()
    events: list[str] = []
    observed: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def fake_build(_: Path) -> TrustedTimeImageAdmission:
        events.append("admission-created")
        return admission

    def fake_artifact_load(_: Path) -> TrustedTimeImageAdmission:
        events.append("artifact-loaded")
        return admission

    def fake_load(path: Path) -> str:
        events.append("secret-loaded")
        return load_runtime_database_url(path)

    def fake_daemon(**_: object) -> LocalDockerDaemonIdentity:
        events.append("daemon-qualified")
        return DAEMON_IDENTITY

    def fake_render(
        *,
        source_image: str,
        supervisor_image: str,
        database_secret_file: Path,
        head_anchor_authority_file: Path,
        head_anchor_auth_secret_file: Path,
        head_anchor_signing_key_secret_file: Path,
    ) -> object:
        assert source_image == SOURCE_IMAGE_ID
        assert supervisor_image == SUPERVISOR_IMAGE_ID
        if database_secret_file != Path("/dev/null"):
            assert head_anchor_authority_file == head_anchor_inputs.authority.path
            assert head_anchor_auth_secret_file == head_anchor_inputs.auth_secret.path
            assert head_anchor_signing_key_secret_file == head_anchor_inputs.signing_key.path
        events.append(f"compose-rendered:{database_secret_file.name}")
        return {"model": "exact"}

    def fake_validate(
        _: object,
        *,
        expected_source_image: str,
        expected_supervisor_image: str,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> None:
        assert expected_source_image == SOURCE_IMAGE_ID
        assert expected_supervisor_image == SUPERVISOR_IMAGE_ID
        events.append(f"compose-qualified:{expected_database_secret_file.name}")

    def fake_topology(
        _: TrustedTimeImageIdentities,
        *,
        environment: dict[str, str],
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> None:
        assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment
        assert expected_database_secret_file == secret.path
        assert expected_head_anchor_authority_file == head_anchor_inputs.authority.path
        assert expected_head_anchor_auth_secret_file == head_anchor_inputs.auth_secret.path
        assert expected_head_anchor_signing_key_secret_file == head_anchor_inputs.signing_key.path
        events.append("runtime-qualified")

    def fake_run(
        argv: tuple[str, ...],
        *,
        environment: Any,
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        exact_environment = cast(dict[str, str], environment)
        observed.append((argv, dict(exact_environment)))
        if argv == compose_argv():
            events.append("compose-up")
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with (
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            side_effect=fake_build,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            side_effect=fake_artifact_load,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_runtime_database_url",
            side_effect=fake_load,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_trusted_time_head_anchor_source_payloads",
            return_value=head_anchor_payloads,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            side_effect=fake_daemon,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            side_effect=fake_render,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.validate_compose_model",
            side_effect=fake_validate,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_created_topology",
            side_effect=fake_topology,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_database_secret",
            return_value=secret,
        ) as materialize,
        patch(
            "scripts.start_trusted_time_supervisor.materialize_trusted_time_head_anchor_inputs",
            return_value=head_anchor_inputs,
        ) as materialize_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_database_secret"
        ) as validate_secret,
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_trusted_time_head_anchor_inputs"
        ) as validate_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_database_secret"
        ) as cleanup_secret,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_trusted_time_head_anchor_inputs"
        ) as cleanup_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor._compose_container_id",
            return_value=SUPERVISOR_CONTAINER_ID,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_mounted_staged_inputs"
        ) as validate_mounted,
        patch("scripts.start_trusted_time_supervisor._wait_for_database_secret_consumption"),
        patch(
            "scripts.start_trusted_time_supervisor.observe_unenrolled_supervisor_terminal"
        ) as observe_terminal,
        patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run),
    ):
        return_code = run_local_topology(env_file=env_file)

    assert return_code == 0
    assert events.index("admission-created") < events.index("secret-loaded")
    assert events.count("artifact-loaded") == 2
    assert events.count("runtime-qualified") == 3
    assert events.count("compose-up") == 1
    materialize.assert_called_once_with(DATABASE_URL)
    materialize_head_anchor.assert_called_once_with(head_anchor_payloads)
    assert validate_secret.call_count == 2
    assert validate_head_anchor.call_count == 2
    assert validate_mounted.call_count == 3
    assert validate_mounted.call_args_list[-1].kwargs["allow_retired_unreadable"] is True
    observe_terminal.assert_not_called()
    cleanup_secret.assert_called_once_with(secret)
    cleanup_head_anchor.assert_called_once_with(head_anchor_inputs)
    up_environment = next(environment for argv, environment in observed if argv == compose_argv())
    assert up_environment["AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"] == str(secret.path)
    assert up_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.authority.path
    )
    assert up_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.auth_secret.path
    )
    assert up_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.signing_key.path
    )
    assert up_environment["AQT_TRUSTED_TIME_SOURCE_IMAGE"] == SOURCE_IMAGE_ID
    assert up_environment["AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"] == SUPERVISOR_IMAGE_ID
    assert "ALPACA_PAPER_API_SECRET" not in up_environment
    assert compose_argv()[-8:] == (
        "--detach",
        "--no-build",
        "--pull",
        "never",
        "--force-recreate",
        "--wait",
        "--wait-timeout",
        "60",
    )
    for argv, environment in observed:
        if argv[0] == "docker" and argv[1] in {"container", "volume"}:
            assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment


def _invoke_mocked_unenrolled_admission(
    tmp_path: Path,
    *,
    compose_returncode: int,
    terminal_evidence: SupervisorTerminalEvidence | None,
    events: list[str],
    topology_error: Exception | None = None,
    stop_results: tuple[bool, ...] = (True,),
    prior_container_id: str | None = None,
    terminal_error: BaseException | None = None,
    teardown_error: Exception | None = None,
) -> int:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    secret = _materialized_secret()
    head_anchor_inputs = _materialized_head_anchor_inputs()
    stop_outcomes = iter(stop_results)
    container_queries = 0

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        if argv != compose_argv():
            raise AssertionError(argv)
        events.append("compose-up")
        return subprocess.CompletedProcess(argv, compose_returncode, "discarded-output", "")

    def fake_topology(*_: object, **__: object) -> None:
        events.append("topology-check")
        if topology_error is not None:
            raise topology_error

    def fake_observe(**_: object) -> SupervisorTerminalEvidence | None:
        events.append("terminal-observe")
        if terminal_error is not None:
            raise terminal_error
        return terminal_evidence

    def fake_optional_container_id(**_: object) -> str | None:
        nonlocal container_queries
        events.append("container-bind")
        container_queries += 1
        return prior_container_id if container_queries == 1 else SUPERVISOR_CONTAINER_ID

    def fake_stop(_: object) -> bool:
        events.append("compose-down")
        return next(stop_outcomes)

    def fake_teardown(**_: object) -> None:
        events.append("teardown-verify")
        if teardown_error is not None:
            raise teardown_error

    def cleanup_secret(_: object) -> None:
        events.append("secret-cleanup")

    def cleanup_anchor(_: object) -> None:
        events.append("anchor-cleanup")

    patchers = (
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch.multiple(
            "scripts.start_trusted_time_supervisor",
            qualify_local_docker_daemon=lambda **_: DAEMON_IDENTITY,
            _capture_trusted_time_volume_identities=lambda **_: VOLUME_IDENTITIES,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_trusted_time_head_anchor_source_payloads",
            return_value=_head_anchor_payloads(),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_database_secret",
            return_value=secret,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_trusted_time_head_anchor_inputs",
            return_value=head_anchor_inputs,
        ),
        patch("scripts.start_trusted_time_supervisor.validate_materialized_database_secret"),
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_trusted_time_head_anchor_inputs"
        ),
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_database_secret",
            side_effect=cleanup_secret,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_trusted_time_head_anchor_inputs",
            side_effect=cleanup_anchor,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_created_topology",
            side_effect=fake_topology,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._compose_container_id",
            return_value=SUPERVISOR_CONTAINER_ID,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._optional_stopped_supervisor_container_id",
            side_effect=fake_optional_container_id,
        ),
        patch("scripts.start_trusted_time_supervisor._validate_mounted_staged_inputs"),
        patch("scripts.start_trusted_time_supervisor._wait_for_database_secret_consumption"),
        patch(
            "scripts.start_trusted_time_supervisor.observe_unenrolled_supervisor_terminal",
            side_effect=fake_observe,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._stop_created_topology",
            side_effect=fake_stop,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_unenrolled_admission_teardown",
            side_effect=fake_teardown,
        ),
        patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run),
    )
    with ExitStack() as stack:
        for patcher in patchers:
            stack.enter_context(patcher)
        return run_local_topology(
            env_file=env_file,
            expect_unenrolled_fail_closed=True,
        )


def test_admission_compose_failure_is_incomplete_even_with_bound_expected_terminal(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )

    with pytest.raises(TrustedTimeSupervisorSecureLaunchIncomplete) as captured:
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=1,
            terminal_evidence=evidence,
            events=events,
        )

    assert events.index("terminal-observe") < events.index("compose-down")
    assert events.index("compose-down") < events.index("teardown-verify")
    assert events.index("teardown-verify") < events.index("anchor-cleanup")
    assert events.index("anchor-cleanup") < events.index("secret-cleanup")
    assert "secret-sentinel" not in str(captured.value)


def test_admission_preserves_unrelated_topology_error_without_observing_terminal(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    topology_error = TrustedTimeImageVerificationError("secret-sentinel topology state disappeared")

    with pytest.raises(TrustedTimeImageVerificationError) as captured:
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=SupervisorTerminalEvidence(
                state="exited",
                exit_code=2,
                status="fatal",
                reason=EXPECTED_TERMINAL_REASON,
            ),
            topology_error=topology_error,
            events=events,
        )

    assert captured.value is topology_error
    assert "terminal-observe" not in events
    assert events.index("compose-down") < events.index("anchor-cleanup")


def test_admission_identity_disappearance_is_an_incomplete_private_race(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )

    with pytest.raises(TrustedTimeSupervisorSecureLaunchIncomplete):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=evidence,
            topology_error=_TrustedTimeSupervisorContainerIdentityUnavailable(
                "trusted-time created container identity is unavailable"
            ),
            events=events,
        )

    assert events.index("terminal-observe") < events.index("compose-down")
    assert events.index("compose-down") < events.index("teardown-verify")
    assert events.index("teardown-verify") < events.index("anchor-cleanup")


def test_admission_rejects_prior_container_before_loading_owner_inputs(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="no prior supervisor container",
    ):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=None,
            events=events,
            prior_container_id=SUPERVISOR_CONTAINER_ID,
        )

    assert events == ["container-bind"]


def test_admission_success_race_observes_terminal_then_always_tears_down(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )

    with pytest.raises(TrustedTimeSupervisorTerminalObserved) as captured:
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=evidence,
            events=events,
        )

    assert events.count("topology-check") == 3
    assert captured.value.image_admission_sha256 == "4" * 64
    assert events.index("anchor-cleanup") < events.index("terminal-observe")
    assert events.index("terminal-observe") < events.index("compose-down")
    assert events.index("compose-down") < events.index("teardown-verify")


def test_admission_timeout_is_fatal_and_tears_down_without_terminal_claim(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    with pytest.raises(TrustedTimeSupervisorTerminalNotObserved):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=None,
            events=events,
        )

    assert events.index("terminal-observe") < events.index("compose-down")
    assert events.count("compose-down") == 1


def test_admission_never_reports_terminal_evidence_when_teardown_fails(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="teardown is unconfirmed",
    ):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=evidence,
            events=events,
            stop_results=(False, False),
        )

    assert events.count("terminal-observe") == 1
    assert events.count("compose-down") == 2
    assert "anchor-cleanup" in events
    assert "secret-cleanup" in events


def test_admission_teardown_validation_failure_still_cleans_staged_inputs(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="teardown is unconfirmed",
    ):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=None,
            topology_error=TrustedTimeSupervisorConfigurationError("topology drift"),
            teardown_error=TrustedTimeSupervisorConfigurationError("remaining network"),
            events=events,
        )

    assert events.index("compose-down") < events.index("teardown-verify")
    assert events.index("teardown-verify") < events.index("anchor-cleanup")
    assert events.index("anchor-cleanup") < events.index("secret-cleanup")


def test_admission_retries_teardown_proof_without_reobserving_terminal(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="teardown is unconfirmed",
    ):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=evidence,
            teardown_error=TrustedTimeSupervisorConfigurationError("remaining network"),
            stop_results=(True, True),
            events=events,
        )

    assert events.count("terminal-observe") == 1
    assert events.count("compose-down") == 2
    assert events.count("teardown-verify") == 2


def test_admission_observer_baseexception_still_tears_down_and_cleans_inputs(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    with pytest.raises(KeyboardInterrupt):
        _invoke_mocked_unenrolled_admission(
            tmp_path,
            compose_returncode=0,
            terminal_evidence=None,
            terminal_error=KeyboardInterrupt(),
            events=events,
        )

    assert events.count("terminal-observe") == 1
    assert events.count("compose-down") == 1
    assert events.index("anchor-cleanup") < events.index("terminal-observe")
    assert events.index("secret-cleanup") < events.index("terminal-observe")
    assert events.index("terminal-observe") < events.index("compose-down")


def test_created_container_validation_requires_exact_image_running_and_health() -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    validate_created_container(
        source,
        expected_image_id=SOURCE_IMAGE_ID,
        expected_image_configuration=_image_configuration("chrony-nts"),
        expected_service="chrony-nts",
        require_healthy=True,
    )

    source[0]["Image"] = SUPERVISOR_IMAGE_ID
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity or state"):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


@pytest.mark.parametrize(
    ("binds", "message"),
    [
        (["other-volume:/var/lib/chrony:rw"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/other:rw"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:ro"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw,z"], "state volume bind"),
        (
            [
                f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw",
                "other-volume:/other:rw",
            ],
            "volume request set",
        ),
    ],
)
def test_source_state_volume_legacy_bind_requires_one_exact_compose_encoding(
    binds: list[str],
    message: str,
) -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    host = cast(dict[str, object], source[0]["HostConfig"])
    host["Binds"] = binds

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


def test_supervisor_runtime_inputs_require_exact_read_only_native_or_desktop_sources() -> None:
    expected = DATABASE_SECRET_ROOT / (".database-secret-" + "a" * 32) / "database-url"
    head_anchor_inputs = _materialized_head_anchor_inputs()
    supervisor = _container_inspection(
        image_id=SUPERVISOR_IMAGE_ID,
        service="trusted-time-supervisor",
        healthy=False,
    )
    validate_created_container(
        supervisor,
        expected_image_id=SUPERVISOR_IMAGE_ID,
        expected_image_configuration=_image_configuration("trusted-time-supervisor"),
        expected_service="trusted-time-supervisor",
        require_healthy=False,
        expected_database_secret_file=expected,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )

    host = cast(dict[str, object], supervisor[0]["HostConfig"])
    mounts = cast(list[dict[str, object]], host["Mounts"])
    for mount in mounts[1:]:
        mount["Source"] = cast(str, mount["Source"]).removeprefix("/host_mnt")
    validate_created_container(
        supervisor,
        expected_image_id=SUPERVISOR_IMAGE_ID,
        expected_image_configuration=_image_configuration("trusted-time-supervisor"),
        expected_service="trusted-time-supervisor",
        require_healthy=False,
        expected_database_secret_file=expected,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )

    mounts[1]["Source"] = "/host_mnt/host_mnt" + str(expected)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="secret bind"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )

    mounts[1]["Source"] = str(expected)
    mounts[2]["ReadOnly"] = False
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="authority bind"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )

    mounts[2]["ReadOnly"] = True
    runtime_mounts = cast(list[dict[str, object]], supervisor[0]["Mounts"])
    runtime_mounts[2]["RW"] = True
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="runtime input mount"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )


@pytest.mark.parametrize(
    ("section", "field_name", "value", "message"),
    [
        ("Config", "Cmd", ["/bin/true"], "command or image"),
        ("Config", "Entrypoint", ["/bin/sh"], "command or image"),
        ("Config", "Env", ["PATH=/usr/bin", "DATABASE_URL=secret"], "environment allowlist"),
        ("HostConfig", "ReadonlyRootfs", False, "isolation or resource"),
        ("HostConfig", "CapAdd", ["SYS_TIME"], "isolation or resource"),
        ("HostConfig", "NetworkMode", "host", "isolation or resource"),
        ("HostConfig", "Mounts", [], "volume request set"),
    ],
)
def test_created_container_validation_rejects_command_cap_network_or_mount_drift(
    section: str,
    field_name: str,
    value: object,
    message: str,
) -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    exact_section = cast(dict[str, object], source[0][section])
    exact_section[field_name] = value

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


def test_stale_socket_volume_stops_and_removes_unqualified_topology(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    secret = _materialized_secret()
    head_anchor_inputs = _materialized_head_anchor_inputs()
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv == compose_argv():
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "down" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with (
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_trusted_time_head_anchor_source_payloads",
            return_value=_head_anchor_payloads(),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_database_secret",
            return_value=secret,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_trusted_time_head_anchor_inputs",
            return_value=head_anchor_inputs,
        ),
        patch("scripts.start_trusted_time_supervisor.validate_materialized_database_secret"),
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_trusted_time_head_anchor_inputs"
        ),
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_database_secret"
        ) as cleanup,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_trusted_time_head_anchor_inputs"
        ) as cleanup_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor._validate_created_topology",
            side_effect=TrustedTimeImageVerificationError(
                "trusted-time socket volume is not the exact tmpfs contract"
            ),
        ),
        patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run),
        pytest.raises(TrustedTimeImageVerificationError, match="exact tmpfs contract"),
    ):
        run_local_topology(env_file=env_file)

    assert "down" in calls[-1]
    cleanup.assert_called_once_with(secret)
    cleanup_head_anchor.assert_called_once_with(head_anchor_inputs)


def test_local_docker_qualification_accepts_one_owned_unix_socket_and_daemon() -> None:
    socket_path = Path("/private/tmp/aqt-local-docker.sock")
    completed = subprocess.CompletedProcess(
        ["docker", "info"],
        0,
        '"LOCAL:DAEMON:1"\n',
        "",
    )
    metadata = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid())
    with (
        patch("scripts.start_trusted_time_supervisor.Path.resolve", return_value=socket_path),
        patch("scripts.start_trusted_time_supervisor.Path.stat", return_value=metadata),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            return_value=completed,
        ) as run,
    ):
        identity = qualify_local_docker_daemon(
            environment={"DOCKER_HOST": f"unix://{socket_path}"},
        )

    assert identity == LocalDockerDaemonIdentity(
        context_name="<DOCKER_HOST>",
        endpoint=f"unix://{socket_path}",
        daemon_id="LOCAL:DAEMON:1",
    )
    assert run.call_args.args[0] == ("docker", "info", "--format", "{{json .ID}}")


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp://docker.example:2376",
        "ssh://operator@docker.example",
        "http://127.0.0.1:2375",
    ],
)
def test_local_docker_qualification_rejects_remote_endpoint_before_daemon_contact(
    endpoint: str,
) -> None:
    with (
        patch("scripts.start_trusted_time_supervisor._run_docker") as run,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="local Unix socket"),
    ):
        qualify_local_docker_daemon(environment={"DOCKER_HOST": endpoint})

    run.assert_not_called()


def test_daemon_identity_change_is_rejected_before_secret_load(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    changed = LocalDockerDaemonIdentity(
        context_name=DAEMON_IDENTITY.context_name,
        endpoint=DAEMON_IDENTITY.endpoint,
        daemon_id="LOCAL:DAEMON:2",
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            side_effect=[DAEMON_IDENTITY, changed],
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch("scripts.start_trusted_time_supervisor.load_runtime_database_url") as load_secret,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity changed"),
    ):
        run_local_topology(env_file=env_file)

    load_secret.assert_not_called()


def test_image_admission_swap_is_rejected_before_secret_load(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    changed = replace(admission, artifact_sha256="f" * 64)
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            side_effect=(admission, changed),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch("scripts.start_trusted_time_supervisor.load_runtime_database_url") as load_secret,
        pytest.raises(
            TrustedTimeSupervisorConfigurationError,
            match="artifact changed before secret load",
        ),
    ):
        run_local_topology(env_file=env_file)

    load_secret.assert_not_called()


def test_chrony_state_volume_requires_exact_compose_owned_local_storage() -> None:
    inspection = [
        {
            "Name": COMPOSE_STATE_VOLUME_NAME,
            "Driver": "local",
            "Scope": "local",
            "Options": None,
            "Labels": {
                "com.docker.compose.project": "autoquanttrader-trusted-time",
                "com.docker.compose.volume": "chrony_state",
            },
        }
    ]
    validate_chrony_state_volume_inspection(inspection)

    inspection[0]["Options"] = {"type": "none", "device": "/host", "o": "bind"}
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="driver drifted"):
        validate_chrony_state_volume_inspection(inspection)


def test_chrony_state_directory_check_is_non_destructive_and_requires_fixed_identity() -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[-3:] == ("-c", "%u:%g:%a", "/var/lib/chrony"):
            return subprocess.CompletedProcess(argv, 0, "10001:10001:755\n", "")
        if "/bin/busybox" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run):
        _validate_chrony_state_directory(SOURCE_CONTAINER_ID)

    access_modes = [argv[-2] for argv in calls if "/bin/busybox" in argv]
    assert access_modes == ["-d", "-r", "-w", "-x"]
    assert all("touch" not in argv and "rm" not in argv for argv in calls)


def test_main_sanitizes_owner_file_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["start-trusted-time-supervisor", "--env-file", "/missing/secret.env"],
    )

    admission = _admission()
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload["status"] == "fatal"
    assert payload["database_secret_disclosed"] is False
    assert "missing" not in output.out
    assert output.err == ""


@pytest.mark.parametrize(
    ("supervisor_reason", "launcher_reason"),
    [
        ("supervision_failed", "supervisor_terminal_unqualified"),
        ("configuration_rejected", "supervisor_terminal_unqualified"),
    ],
)
def test_admission_main_emits_only_fixed_terminal_projection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    supervisor_reason: str,
    launcher_reason: str,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=supervisor_reason,
    )
    terminal_error = TrustedTimeSupervisorTerminalUnqualified(evidence)
    with (
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=terminal_error,
        ) as run,
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    run.assert_called_once_with(
        env_file=Path("/secret-sentinel.env"),
        image_admission_artifact=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        expect_unenrolled_fail_closed=True,
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert "secret-sentinel" not in output.out
    assert json.loads(output.out) == {
        "database_secret_disclosed": False,
        "new_exposure_authorized": False,
        "reason": launcher_reason,
        "service": "trusted-time-local-launcher",
        "status": "fatal",
        "supervisor_exit_code": 2,
        "supervisor_reason": supervisor_reason,
        "supervisor_state": "exited",
        "supervisor_status": "fatal",
    }


def test_admission_main_retains_exact_receipt_and_returns_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    admission_id = "123e4567-e89b-42d3-a456-426614174000"
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )
    encoded = build_unenrolled_admission_receipt(
        admission_id=admission_id,
        image_admission_sha256="4" * 64,
        terminal_evidence=evidence,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )

    def retain_and_emit(
        artifact_dir: Path,
        receipt: bytes,
        *,
        emit: object,
    ) -> Path:
        assert artifact_dir == DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR
        assert receipt == encoded
        assert callable(emit)
        emit(receipt)
        return artifact_dir / "content-addressed.json"

    with (
        patch(
            "scripts.start_trusted_time_supervisor._new_unenrolled_admission_id",
            return_value=admission_id,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorTerminalObserved(
                evidence,
                image_admission_sha256="4" * 64,
            ),
        ) as run,
        patch(
            "scripts.start_trusted_time_supervisor.write_unenrolled_admission_receipt",
            side_effect=retain_and_emit,
        ) as write,
    ):
        main()

    run.assert_called_once_with(
        env_file=Path("/secret-sentinel.env"),
        image_admission_artifact=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        expect_unenrolled_fail_closed=True,
    )
    write.assert_called_once()
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.encode("ascii") == encoded
    payload = json.loads(output.out)
    assert payload["status"] == "admitted"
    assert payload["reason"] == "expected_unenrolled_fail_closed_observed"
    assert "secret-sentinel" not in output.out


def test_admission_output_rejects_short_write_without_flushing() -> None:
    flushed = False

    def flush() -> None:
        nonlocal flushed
        flushed = True

    output = SimpleNamespace(write=lambda _: 0, flush=flush)
    with (
        patch("scripts.start_trusted_time_supervisor.sys.stdout", output),
        pytest.raises(TrustedTimeSupervisorAdmissionOutputError),
    ):
        _emit_unenrolled_admission_receipt(_admitted_receipt())

    assert flushed is False


def test_admission_main_partial_race_is_fatal_without_artifact(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorSecureLaunchIncomplete("secret-sentinel"),
        ),
        patch("scripts.start_trusted_time_supervisor.write_unenrolled_admission_receipt") as write,
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    write.assert_not_called()
    output = capsys.readouterr()
    assert output.err == ""
    assert "secret-sentinel" not in output.out
    assert json.loads(output.out)["reason"] == "secure_launch_incomplete"


def test_admission_main_sanitizes_receipt_retention_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorTerminalObserved(
                evidence,
                image_admission_sha256="4" * 64,
            ),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.write_unenrolled_admission_receipt",
            side_effect=RuntimeError("secret-canary"),
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    assert output.err == ""
    assert "secret-canary" not in output.out
    assert json.loads(output.out)["reason"] == "admission_artifact_rejected"


def test_admission_main_reports_unconfirmed_receipt_retention_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorTerminalObserved(
                evidence,
                image_admission_sha256="4" * 64,
            ),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.write_unenrolled_admission_receipt",
            side_effect=TrustedTimeSupervisorAdmissionRetentionUnconfirmed("secret-canary"),
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "secret-canary" not in output.err
    assert json.loads(output.err)["reason"] == "admission_retention_unconfirmed"


def test_admission_main_rolls_back_receipt_when_canonical_output_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    admission_id = "123e4567-e89b-42d3-a456-426614174000"
    evidence = SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=EXPECTED_TERMINAL_REASON,
    )
    artifact_dir = (tmp_path / "artifacts" / "trusted-time").resolve()

    def write_at_test_root(
        directory: Path,
        receipt: bytes,
        *,
        emit: object,
    ) -> Path:
        assert callable(emit)
        return write_unenrolled_admission_receipt(
            directory,
            receipt,
            ignored_root=tmp_path / "artifacts",
            emit=emit,
        )

    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor._new_unenrolled_admission_id",
            return_value=admission_id,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorTerminalObserved(
                evidence,
                image_admission_sha256="4" * 64,
            ),
        ),
        patch(
            "scripts.start_trusted_time_supervisor._emit_unenrolled_admission_receipt",
            side_effect=TrustedTimeSupervisorAdmissionOutputError("secret-canary"),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.write_unenrolled_admission_receipt",
            side_effect=write_at_test_root,
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    assert artifact_dir.is_dir()
    assert list(artifact_dir.iterdir()) == []
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""


def test_admission_main_never_claims_a_terminal_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "start-trusted-time-supervisor",
            "--env-file",
            "/secret-sentinel.env",
            "--expect-unenrolled-fail-closed",
        ],
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.run_local_topology",
            side_effect=TrustedTimeSupervisorTerminalNotObserved("secret-sentinel"),
        ),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    assert output.err == ""
    assert "secret-sentinel" not in output.out
    assert json.loads(output.out)["reason"] == "expected_terminal_not_observed"
