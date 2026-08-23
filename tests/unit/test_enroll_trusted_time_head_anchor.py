from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

import scripts.enroll_trusted_time_head_anchor as launcher
import scripts.start_trusted_time_supervisor as supervisor_launcher
from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from apps.trusted_time_supervisor.first_enrollment import (
    TrustedTimeFirstEnrollmentOperationMode,
)
from packages.domain.trusted_time_enrollment_evidence import (
    decode_confirmed_first_enrollment,
)
from scripts.start_trusted_time_supervisor import (
    FIRST_ENROLLMENT_COMMAND,
    FIRST_ENROLLMENT_SERVICE,
    LocalDockerDaemonIdentity,
    SupervisorTerminalEvidence,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
    build_unenrolled_admission_receipt,
)
from scripts.verify_trusted_time_images import (
    TrustedTimeImageAdmission,
    TrustedTimeImageIdentities,
    _CurrentTrustedTimeImageAdmissionSnapshot,
    _make_current_admission_snapshot,
    _make_verified_images,
    _VerifiedTrustedTimeImages,
)


def _process_result[T: (bytes, str)](
    args: list[str] | tuple[str, ...],
    returncode: int,
    stdout: T,
    stderr: T,
) -> tuple[tuple[str, ...], int, T, T]:
    return (tuple(args), returncode, stdout, stderr)


GIT_REVISION = "a" * 40
IMAGE_ADMISSION_SHA256 = "b" * 64
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000"
ADMISSION_ID = "223e4567-e89b-42d3-a456-426614174001"
RECOVERY_OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"
CONTAINER_ID = "d" * 64
SECRET_CANARY = "first-enrollment-host-secret-canary"


def _approved_launch() -> TrustedTimeApprovedLaunch:
    return TrustedTimeApprovedLaunch(
        git_revision=GIT_REVISION,
        image_admission_sha256=IMAGE_ADMISSION_SHA256,
        source_image_id=SOURCE_IMAGE_ID,
        supervisor_image_id=SUPERVISOR_IMAGE_ID,
    )


def _approval(
    *,
    operation_mode: TrustedTimeFirstEnrollmentOperationMode = (
        TrustedTimeFirstEnrollmentOperationMode.NEW
    ),
    operation_id: str = OPERATION_ID,
    unenrolled_admission_sha256: str = "9" * 64,
) -> launcher.TrustedTimeFirstEnrollmentApproval:
    return launcher.TrustedTimeFirstEnrollmentApproval(
        operation_id=operation_id,
        operation_mode=operation_mode,
        approved_launch=_approved_launch(),
        unenrolled_admission_sha256=unenrolled_admission_sha256,
        anchor_authority_sha256="3" * 64,
        deployment_identity_sha256="4" * 64,
        runtime_database_identity_sha256="5" * 64,
        anchor_project_identity_sha256="6" * 64,
        source_authority_sha256="7" * 64,
        signing_public_key_sha256="8" * 64,
        host_identity_sha256="a" * 64,
        principal_identity_sha256="b" * 64,
        bucket_identity_sha256="c" * 64,
    )


def _unenrolled_receipt() -> bytes:
    return build_unenrolled_admission_receipt(
        admission_id=ADMISSION_ID,
        approved_launch=_approved_launch(),
        terminal_evidence=SupervisorTerminalEvidence(
            state="exited",
            exit_code=2,
            status="fatal",
            reason="head_anchor_remote_history_absent_enrollment_not_approved",
        ),
    )


def _claim_artifact_bytes(
    approval: launcher.TrustedTimeFirstEnrollmentApproval,
) -> bytes:
    return _claim_artifact_bytes_from_approval_payload(approval.payload())


def _claim_artifact_bytes_from_approval_payload(
    approval_payload: dict[str, object],
) -> bytes:
    payload = dict(approval_payload)
    payload.update({field_name: False for field_name in launcher._AUTHORITY_FIELDS})
    payload.update(
        {
            "approval_sha256": hashlib.sha256(
                launcher._canonical_json_bytes(approval_payload)
            ).hexdigest(),
            "authority_granted": False,
            "claim_contract_version": launcher.FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION,
            "new_exposure_authorized": False,
            "service": "trusted-time-first-enrollment-host-launcher",
            "status": "claimed",
        }
    )
    return launcher._canonical_json_bytes(payload)


def _recovery_approval(
    *,
    prior_new_approval: launcher.TrustedTimeFirstEnrollmentApproval,
    prior_new_claim_sha256: str,
    approved_launch: TrustedTimeApprovedLaunch | None = None,
) -> launcher.TrustedTimeFirstEnrollmentApproval:
    return replace(
        _approval(),
        operation_id=RECOVERY_OPERATION_ID,
        operation_mode=TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
        approved_launch=approved_launch or prior_new_approval.approved_launch,
        unenrolled_admission_sha256=prior_new_approval.unenrolled_admission_sha256,
        prior_new_operation_id=prior_new_approval.operation_id,
        prior_new_claim_sha256=prior_new_claim_sha256,
    )


def _image_admission(*, created_monotonic_ns: int = 1_000_000_000) -> TrustedTimeImageAdmission:
    return TrustedTimeImageAdmission(
        path=Path("/tmp/trusted-time-image-admission.json"),
        identities=TrustedTimeImageIdentities(
            source_id=SOURCE_IMAGE_ID,
            supervisor_id=SUPERVISOR_IMAGE_ID,
        ),
        boot_session_id="darwin:11111111-2222-3333-4444-555555555555",
        git_revision=GIT_REVISION,
        source_revision_sha256="e" * 64,
        artifact_sha256=IMAGE_ADMISSION_SHA256,
        created_at_utc="2026-08-08T16:00:00.000000Z",
        created_monotonic_ns=created_monotonic_ns,
    )


def _image_admission_snapshot(
    *,
    created_monotonic_ns: int = 1_000_000_000,
) -> _CurrentTrustedTimeImageAdmissionSnapshot:
    admission = _image_admission(created_monotonic_ns=created_monotonic_ns)
    path = os.fspath(admission.path)
    identity = (1, 2, stat.S_IFREG | 0o600, os.geteuid(), os.getegid(), 1, 2, 3, 4)
    return _make_current_admission_snapshot(
        path=path,
        ignored_root=os.fspath(launcher.IGNORED_ARTIFACT_ROOT),
        archive_path=path,
        source_id=admission.identities.source_id,
        supervisor_id=admission.identities.supervisor_id,
        boot_session_id=admission.boot_session_id,
        git_revision=admission.git_revision,
        source_revision_sha256=admission.source_revision_sha256,
        supervisor_executable_import_manifest_sha256="d" * 64,
        artifact_sha256=admission.artifact_sha256,
        created_at_utc=admission.created_at_utc,
        created_monotonic_ns=admission.created_monotonic_ns,
        encoded=b"{}",
        directory_identity=identity,
        file_identity=identity,
        archive_directory_identity=identity,
        archive_file_identity=identity,
    )


def _verified_images() -> _VerifiedTrustedTimeImages:
    return _make_verified_images(
        source_id=SOURCE_IMAGE_ID,
        supervisor_id=SUPERVISOR_IMAGE_ID,
        supervisor_manifest_sha256="d" * 64,
    )


def _terminal_payload(
    approval: launcher.TrustedTimeFirstEnrollmentApproval,
    *,
    status: str = "confirmed",
    reason: str = "first_enrollment_confirmed",
    operation_mode: TrustedTimeFirstEnrollmentOperationMode | None = None,
    disposition: str = "new_intent_completed",
) -> dict[str, object]:
    payload: dict[str, object] = {field_name: False for field_name in launcher._AUTHORITY_FIELDS}
    payload.update(launcher._expected_identity_payload(approval))
    payload.update(
        {
            "anchor_intent_semantic_sha256": "0" * 64,
            "anchor_sequence": 1,
            "candidate_remote_readback_sha256": "d" * 64,
            "checkpoint_reason": "enrollment",
            "completion_disposition": disposition,
            "contract_version": launcher.TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
            "current_anchor_semantic_sha256": "e" * 64,
            "current_anchor_sha256": "d" * 64,
            "current_host_head_sha256": "f" * 64,
            "database_secret_disclosed": False,
            "full_audit_completed": True,
            "idempotent_duplicate_count": (
                None if disposition == "confirmed_receipt_reobserved" else 0
            ),
            "operation_mode": (operation_mode or approval.operation_mode).value,
            "pending_intent_recovered": disposition == "pending_intent_recovered",
            "reason": reason,
            "receipt_semantic_sha256": "9" * 64,
            "remote_namespace_sha256": "8" * 64,
            "service": FIRST_ENROLLMENT_SERVICE,
            "status": status,
            "uploaded_anchor_count": (None if disposition == "confirmed_receipt_reobserved" else 1),
        }
    )
    return payload


def _fatal_terminal_payload(
    approval: launcher.TrustedTimeFirstEnrollmentApproval,
    *,
    reason: str = "provider_unavailable_before_commit",
) -> dict[str, object]:
    payload = _terminal_payload(approval)
    payload.update({field_name: None for field_name in launcher._RESULT_DIGEST_FIELDS})
    payload.update(
        {
            "anchor_sequence": None,
            "checkpoint_reason": None,
            "completion_disposition": None,
            "full_audit_completed": False,
            "idempotent_duplicate_count": None,
            "pending_intent_recovered": False,
            "reason": reason,
            "remote_namespace_sha256": None,
            "status": "fatal",
            "uploaded_anchor_count": None,
        }
    )
    return payload


def _completed_unconfirmed_payload(
    approval: launcher.TrustedTimeFirstEnrollmentApproval,
) -> dict[str, object]:
    payload = _terminal_payload(approval)
    payload.update(
        {
            "reason": "first_enrollment_completed_postconditions_unconfirmed",
            "remote_namespace_sha256": None,
            "status": "fatal",
        }
    )
    return payload


def _all_gates(**overrides: bool) -> dict[str, bool]:
    gates = {
        "final_approval_state_validated": True,
        "final_image_admission_fresh": True,
        "runtime_inputs_retired": True,
        "secure_launch_validated": True,
        "single_use_claim_retained": True,
        "state_volumes_preserved": True,
        "terminal_evidence_qualified": True,
        "topology_removed": True,
    }
    gates.update(overrides)
    return gates


def _terminal_inspection(*, exit_code: int) -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "Cmd": list(FIRST_ENROLLMENT_COMMAND),
                "Labels": {
                    "com.docker.compose.project": "autoquanttrader-trusted-time",
                    "com.docker.compose.service": FIRST_ENROLLMENT_SERVICE,
                },
            },
            "Id": CONTAINER_ID,
            "Image": SUPERVISOR_IMAGE_ID,
            "RestartCount": 0,
            "State": {
                "Dead": False,
                "Error": "",
                "ExitCode": exit_code,
                "OOMKilled": False,
                "Running": False,
                "Status": "exited",
            },
        }
    ]


def _stale_enrollment_input_paths(runtime_root: Path) -> tuple[Path, ...]:
    return (
        runtime_root
        / (".database-secret-" + "a" * 32)
        / supervisor_launcher.DATABASE_SECRET_FILE_NAME,
        runtime_root
        / (".head-anchor-authority-" + "b" * 32)
        / supervisor_launcher.HEAD_ANCHOR_AUTHORITY_FILE_NAME,
        runtime_root
        / (".head-anchor-auth-" + "c" * 32)
        / supervisor_launcher.HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
        runtime_root
        / (".head-anchor-signing-key-" + "d" * 32)
        / supervisor_launcher.HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
    )


def _stage_stale_enrollment_inputs(runtime_root: Path) -> tuple[Path, ...]:
    ignored_root = runtime_root.parent.parent
    trusted_time_root = runtime_root.parent
    ignored_root.mkdir(parents=True, mode=0o700)
    ignored_root.chmod(0o700)
    trusted_time_root.mkdir(mode=0o700)
    trusted_time_root.chmod(0o700)
    runtime_root.mkdir(mode=0o700)
    runtime_root.chmod(0o700)
    paths = _stale_enrollment_input_paths(runtime_root)
    for path in paths:
        path.parent.mkdir(mode=0o700)
        path.parent.chmod(0o700)
        path.write_bytes(SECRET_CANARY.encode("ascii"))
        path.chmod(0o400)
    return paths


def _stale_enrollment_image_configuration() -> dict[str, object]:
    return {
        "Cmd": ["autoquant-trusted-time-supervisor"],
        "Entrypoint": None,
        "Env": [
            "PATH=/opt/autoquant/trusted-time/bin:/usr/local/bin:/usr/local/sbin:"
            "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "ExposedPorts": None,
        "User": "10001:10001",
        "WorkingDir": "/workspace",
    }


def _stale_enrollment_inspection(
    source_paths: tuple[Path, ...],
    *,
    running: bool = True,
    legacy_binds: bool = False,
) -> list[dict[str, object]]:
    runtime_targets = (
        supervisor_launcher.DATABASE_SECRET_RUNTIME_PATH,
        supervisor_launcher.HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
        supervisor_launcher.HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
        supervisor_launcher.HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    )
    host_mounts = [
        {
            "ReadOnly": True,
            "Source": str(source),
            "Target": target,
            "Type": "bind",
        }
        for source, target in zip(source_paths, runtime_targets, strict=True)
    ]
    runtime_mounts = [
        {
            "Destination": target,
            "RW": False,
            "Source": str(source),
            "Type": "bind",
        }
        for source, target in zip(source_paths, runtime_targets, strict=True)
    ]
    image_configuration = _stale_enrollment_image_configuration()
    runtime_environment = [
        *image_configuration["Env"],  # type: ignore[misc]
        "AQT_TRUSTED_TIME_DATABASE_URL_FILE=" + supervisor_launcher.DATABASE_SECRET_RUNTIME_PATH,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH="
        + supervisor_launcher.HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE="
        + supervisor_launcher.HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE="
        + supervisor_launcher.HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    ]
    return [
        {
            "Config": {
                **image_configuration,
                "Cmd": list(FIRST_ENROLLMENT_COMMAND),
                "Env": runtime_environment,
                "Healthcheck": None,
                "Labels": {
                    "com.docker.compose.project": "autoquanttrader-trusted-time",
                    "com.docker.compose.service": FIRST_ENROLLMENT_SERVICE,
                },
            },
            "HostConfig": {
                "Binds": (
                    [
                        f"{source}:{target}:ro"
                        for source, target in zip(source_paths, runtime_targets, strict=True)
                    ]
                    if legacy_binds
                    else None
                ),
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "DeviceCgroupRules": None,
                "Devices": None,
                "Init": True,
                "Memory": 268_435_456,
                "Mounts": [] if legacy_binds else host_mounts,
                "NanoCpus": 500_000_000,
                "NetworkMode": supervisor_launcher.COMPOSE_NETWORK_NAME,
                "PidsLimit": 64,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
                "SecurityOpt": ["no-new-privileges:true"],
                "Tmpfs": {
                    "/tmp": ("rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700")
                },
            },
            "Id": CONTAINER_ID,
            "Image": SUPERVISOR_IMAGE_ID,
            "Mounts": runtime_mounts,
            "NetworkSettings": {"Networks": {supervisor_launcher.COMPOSE_NETWORK_NAME: {}}},
            "RestartCount": 0,
            "State": {
                "Dead": False,
                "Error": "",
                "ExitCode": 0 if running else 2,
                "OOMKilled": False,
                "Running": running,
                "Status": "running" if running else "exited",
            },
        }
    ]


class _ReachedOwnerEnvironment(RuntimeError):
    pass


def _configure_stale_enrollment_preflight(
    monkeypatch: pytest.MonkeyPatch,
    *,
    approval: launcher.TrustedTimeFirstEnrollmentApproval,
    inspection: list[dict[str, object]],
    source_paths: tuple[Path, ...],
    project_ids: tuple[str, ...] = (CONTAINER_ID,),
) -> tuple[
    list[str],
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
    LocalDockerDaemonIdentity,
    TrustedTimeVolumeIdentities,
]:
    events: list[str] = []
    daemon_identity = LocalDockerDaemonIdentity(
        context_name="desktop-linux",
        endpoint="unix:///local/docker.sock",
        daemon_id="LOCAL:DAEMON:1",
    )
    volume_identities = TrustedTimeVolumeIdentities(
        socket_sha256="5" * 64,
        state_sha256="6" * 64,
    )
    admission = _image_admission_snapshot()
    prior_claim = _claim_artifact_bytes(_approval())
    monkeypatch.setattr(
        supervisor_launcher,
        "DATABASE_SECRET_ROOT",
        source_paths[0].parent.parent,
    )
    monkeypatch.setattr(
        launcher,
        "DATABASE_SECRET_ROOT",
        source_paths[0].parent.parent,
        raising=False,
    )
    monkeypatch.setattr(
        launcher,
        "IGNORED_ARTIFACT_ROOT",
        source_paths[0].parents[3],
    )
    monkeypatch.setattr(launcher, "_trusted_time_artifact_directory", lambda path: path)
    monkeypatch.setattr(
        launcher,
        "_approved_image_admission_path",
        lambda path, _launch: path,
    )
    monkeypatch.setattr(
        launcher,
        "load_approved_unenrolled_admission",
        Mock(return_value=_unenrolled_receipt()),
    )
    monkeypatch.setattr(
        launcher,
        "load_approved_prior_new_claim",
        Mock(
            return_value=(
                None
                if approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW
                else prior_claim
            )
        ),
    )
    monkeypatch.setattr(launcher, "_require_prior_claim_receipt_binding", Mock())
    monkeypatch.setattr(launcher, "_require_approved_git_revision", Mock())
    monkeypatch.setattr(launcher, "_minimal_docker_environment", lambda: {})
    monkeypatch.setattr(
        launcher,
        "qualify_local_docker_daemon",
        Mock(return_value=daemon_identity),
    )
    monkeypatch.setattr(
        launcher,
        "_load_approved_image_admission",
        Mock(return_value=admission),
    )
    monkeypatch.setattr(launcher, "_require_image_admission_reserve", Mock())
    monkeypatch.setattr(
        launcher,
        "_verify_images_with_manifest",
        Mock(return_value=_verified_images()),
    )
    monkeypatch.setattr(launcher, "_require_same_local_daemon", Mock())
    monkeypatch.setattr(
        launcher,
        "_head_reviewed_input_payload",
        Mock(return_value=b"services: {}\n"),
    )
    monkeypatch.setattr(
        launcher,
        "_validate_runtime_compose_payload",
        lambda payload: payload,
    )
    monkeypatch.setattr(launcher, "render_compose_model", Mock(return_value={}))
    monkeypatch.setattr(launcher, "validate_compose_model", Mock())
    monkeypatch.setattr(
        launcher,
        "_compose_project_container_ids",
        Mock(side_effect=(project_ids, project_ids)),
    )
    monkeypatch.setattr(
        launcher,
        "_enrollment_container_id",
        Mock(return_value=CONTAINER_ID),
    )

    def capture_volumes(*, environment: object) -> TrustedTimeVolumeIdentities:
        assert environment == {}
        events.append("capture-volumes")
        return volume_identities

    monkeypatch.setattr(
        launcher,
        "_capture_trusted_time_volume_identities",
        capture_volumes,
    )
    monkeypatch.setattr(
        launcher,
        "_inspect_container",
        Mock(return_value=inspection),
    )
    monkeypatch.setattr(
        launcher,
        "_inspect_image_configuration",
        Mock(return_value=_stale_enrollment_image_configuration()),
    )

    stop = Mock()

    def stop_topology(*, environment: object, compose_payload: bytes) -> bool:
        assert environment is not None
        assert compose_payload == b"services: {}\n"
        assert all(path.exists() for path in source_paths)
        events.append("down")
        stop()
        return True

    monkeypatch.setattr(launcher, "_stop_enrollment_topology", stop_topology)
    release = Mock(side_effect=AssertionError("stale topology was released"))
    monkeypatch.setattr(launcher, "_release_enrollment_container", release)
    teardown = Mock()

    def validate_teardown(**kwargs: object) -> None:
        events.append("validate-teardown")
        teardown(**kwargs)

    monkeypatch.setattr(
        launcher,
        "_validate_unenrolled_admission_teardown",
        validate_teardown,
    )
    load_runtime = Mock()

    def open_owner_environment(_path: Path) -> object:
        assert all(not path.exists() for path in source_paths)
        events.append("owner-env")
        load_runtime()
        raise _ReachedOwnerEnvironment

    monkeypatch.setattr(
        launcher,
        "load_trusted_time_runtime_configuration",
        open_owner_environment,
    )
    read = Mock(side_effect=AssertionError("stale input content was read"))
    monkeypatch.setattr(launcher.os, "read", read)
    return (
        events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        daemon_identity,
        volume_identities,
    )


@pytest.mark.parametrize("running", [True, False])
@pytest.mark.parametrize("legacy_binds", [False, True], ids=("mounts", "legacy-binds"))
def test_recovery_removes_one_exact_stale_enrollment_topology_before_owner_env(
    running: bool,
    legacy_binds: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    prior_new_approval = _approval()
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=hashlib.sha256(
            _claim_artifact_bytes(prior_new_approval)
        ).hexdigest(),
    )
    (
        events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        daemon_identity,
        volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=recovery,
        inspection=_stale_enrollment_inspection(
            source_paths,
            running=running,
            legacy_binds=legacy_binds,
        ),
        source_paths=source_paths,
    )

    with pytest.raises(_ReachedOwnerEnvironment):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=recovery,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=tmp_path / "artifacts" / "trusted-time",
        )

    stop.assert_called_once_with()
    release.assert_not_called()
    load_runtime.assert_called_once_with()
    read.assert_not_called()
    assert all(not path.exists() and not path.parent.exists() for path in source_paths)
    assert events.index("capture-volumes") < events.index("down")
    assert events.index("down") < events.index("validate-teardown")
    assert events.index("validate-teardown") < events.index("owner-env")
    assert any(
        call_kwargs.kwargs.get("daemon_identity") == daemon_identity
        and call_kwargs.kwargs.get("expected_volume_identities") == volume_identities
        for call_kwargs in teardown.call_args_list
    )


def test_new_enrollment_cleans_an_exact_preclaim_stale_topology_before_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    approval = _approval()
    (
        events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        _daemon_identity,
        _volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=approval,
        inspection=_stale_enrollment_inspection(source_paths),
        source_paths=source_paths,
    )

    with pytest.raises(_ReachedOwnerEnvironment):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=approval,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=tmp_path / "artifacts" / "trusted-time",
        )

    stop.assert_called_once_with()
    release.assert_not_called()
    assert teardown.call_count >= 1
    load_runtime.assert_called_once_with()
    read.assert_not_called()
    assert all(not path.exists() and not path.parent.exists() for path in source_paths)
    assert events.index("capture-volumes") < events.index("down")
    assert events.index("down") < events.index("validate-teardown")
    assert events.index("validate-teardown") < events.index("owner-env")


def test_new_enrollment_cleans_exact_orphaned_inputs_after_empty_topology_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    approval = _approval()
    (
        events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        _daemon_identity,
        _volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=approval,
        inspection=[],
        source_paths=source_paths,
        project_ids=(),
    )

    with pytest.raises(_ReachedOwnerEnvironment):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=approval,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=tmp_path / "artifacts" / "trusted-time",
        )

    stop.assert_called_once_with()
    release.assert_not_called()
    assert teardown.call_count == 2
    load_runtime.assert_called_once_with()
    read.assert_not_called()
    assert all(not path.exists() and not path.parent.exists() for path in source_paths)
    assert events.index("capture-volumes") < events.index("down")
    assert events.index("down") < events.index("validate-teardown")
    assert events.index("validate-teardown") < events.index("owner-env")


def test_empty_topology_rejects_unknown_orphan_without_reading_or_releasing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    unknown_directory = runtime_root / ".unknown-staged-input"
    unknown_directory.mkdir(mode=0o700)
    unknown_file = unknown_directory / "secret-canary"
    unknown_file.write_bytes(SECRET_CANARY.encode("ascii"))
    unknown_file.chmod(0o400)
    approval = _approval()
    (
        _events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        _daemon_identity,
        _volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=approval,
        inspection=[],
        source_paths=source_paths,
        project_ids=(),
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="input inventory is invalid",
    ):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=approval,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=tmp_path / "artifacts" / "trusted-time",
        )

    stop.assert_called_once_with()
    release.assert_not_called()
    teardown.assert_called_once()
    load_runtime.assert_not_called()
    read.assert_not_called()
    assert unknown_file.exists() and unknown_directory.exists()
    assert all(path.exists() and path.parent.exists() for path in source_paths)


def test_new_enrollment_with_any_retained_claim_rejects_before_stale_inspection_or_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    artifact_dir = runtime_root.parent
    claim_path = artifact_dir / (
        "trusted-time-first-enrollment-claim-123e4567-e89b-42d3-a456-426614174000.json"
    )
    claim_path.write_bytes(b"{}\n")
    claim_path.chmod(0o600)
    approval = _approval()
    require_no_prior_claim = launcher._require_new_operation_has_no_prior_claim
    (
        _events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        _daemon_identity,
        _volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=approval,
        inspection=_stale_enrollment_inspection(source_paths),
        source_paths=source_paths,
    )
    monkeypatch.setattr(
        launcher,
        "_require_new_operation_has_no_prior_claim",
        require_no_prior_claim,
    )
    inspect = Mock(side_effect=AssertionError("retained-claim topology was inspected"))
    monkeypatch.setattr(launcher, "_inspect_container", inspect)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="new enrollment is blocked by a retained claim",
    ):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=approval,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=artifact_dir,
        )

    inspect.assert_not_called()
    stop.assert_not_called()
    release.assert_not_called()
    teardown.assert_not_called()
    load_runtime.assert_not_called()
    read.assert_not_called()
    assert claim_path.exists()
    assert all(path.exists() and path.parent.exists() for path in source_paths)


@pytest.mark.parametrize(
    "drift",
    [
        "extra_container",
        "service",
        "image",
        "command",
        "mount_set",
        "source_path",
    ],
)
def test_recovery_rejects_stale_topology_drift_without_down_or_release(
    drift: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source_paths = _stage_stale_enrollment_inputs(runtime_root)
    inspection = _stale_enrollment_inspection(source_paths)
    project_ids = (CONTAINER_ID,)
    if drift == "extra_container":
        project_ids = (CONTAINER_ID, "e" * 64)
    elif drift == "service":
        inspection[0]["Config"]["Labels"][  # type: ignore[index]
            "com.docker.compose.service"
        ] = "trusted-time-supervisor"
    elif drift == "image":
        inspection[0]["Image"] = "sha256:" + "9" * 64
    elif drift == "command":
        inspection[0]["Config"]["Cmd"] = ["/bin/false"]  # type: ignore[index]
    elif drift == "mount_set":
        runtime_mounts = inspection[0]["Mounts"]
        assert isinstance(runtime_mounts, list)
        inspection[0]["Mounts"] = runtime_mounts[:-1]
    else:
        host = inspection[0]["HostConfig"]
        assert isinstance(host, dict)
        host_mounts = host["Mounts"]
        assert isinstance(host_mounts, list)
        changed_mount = copy.deepcopy(host_mounts[0])
        assert isinstance(changed_mount, dict)
        changed_mount["Source"] = "/tmp/unapproved-stale-input"
        host_mounts[0] = changed_mount
    prior_new_approval = _approval()
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=hashlib.sha256(
            _claim_artifact_bytes(prior_new_approval)
        ).hexdigest(),
    )
    (
        _events,
        stop,
        release,
        teardown,
        load_runtime,
        read,
        _daemon_identity,
        _volume_identities,
    ) = _configure_stale_enrollment_preflight(
        monkeypatch,
        approval=recovery,
        inspection=inspection,
        source_paths=source_paths,
        project_ids=project_ids,
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        launcher._run_first_enrollment_under_lock(
            env_file=tmp_path / "trusted-time-launch.env",
            approval=recovery,
            image_admission_artifact=tmp_path / "image-admission.json",
            artifact_dir=tmp_path / "artifacts" / "trusted-time",
        )

    stop.assert_not_called()
    release.assert_not_called()
    teardown.assert_not_called()
    load_runtime.assert_not_called()
    read.assert_not_called()
    assert all(path.exists() and path.parent.exists() for path in source_paths)


def _cli_arguments(
    *,
    recover_pending: bool = False,
    prior_new_operation_id: str = OPERATION_ID,
    prior_new_claim_sha256: str = "f" * 64,
) -> list[str]:
    approval = _approval()
    arguments = [
        "trusted-time-enroll-first",
        "--env-file",
        "/owner/trusted-time-launch.env",
        "--operation-id",
        RECOVERY_OPERATION_ID if recover_pending else approval.operation_id,
        "--approved-git-revision",
        approval.approved_launch.git_revision,
        "--approved-image-admission-sha256",
        approval.approved_launch.image_admission_sha256,
        "--approved-source-image-id",
        approval.approved_launch.source_image_id,
        "--approved-supervisor-image-id",
        approval.approved_launch.supervisor_image_id,
        "--unenrolled-admission-sha256",
        approval.unenrolled_admission_sha256,
        "--anchor-authority-sha256",
        approval.anchor_authority_sha256,
        "--deployment-identity-sha256",
        approval.deployment_identity_sha256,
        "--runtime-database-identity-sha256",
        approval.runtime_database_identity_sha256,
        "--anchor-project-identity-sha256",
        approval.anchor_project_identity_sha256,
        "--source-authority-sha256",
        approval.source_authority_sha256,
        "--signing-public-key-sha256",
        approval.signing_public_key_sha256,
        "--host-identity-sha256",
        approval.host_identity_sha256,
        "--principal-identity-sha256",
        approval.principal_identity_sha256,
        "--bucket-identity-sha256",
        approval.bucket_identity_sha256,
    ]
    if recover_pending:
        arguments.extend(
            [
                "--recover-pending",
                "--prior-new-operation-id",
                prior_new_operation_id,
                "--prior-new-claim-sha256",
                prior_new_claim_sha256,
            ]
        )
    return arguments


def test_approval_validates_exact_types_and_has_one_canonical_hash() -> None:
    approval = _approval()
    encoded = launcher._canonical_json_bytes(approval.payload())

    assert approval.approval_sha256 == hashlib.sha256(encoded).hexdigest()
    assert encoded == launcher._canonical_json_bytes(approval.payload())
    assert set(approval.payload()) == {
        "anchor_authority_sha256",
        "anchor_project_identity_sha256",
        "approved_git_revision",
        "approved_image_admission_sha256",
        "approved_source_image_id",
        "approved_supervisor_image_id",
        "bucket_identity_sha256",
        "contract_version",
        "deployment_identity_sha256",
        "host_identity_sha256",
        "operation_id",
        "operation_mode",
        "prior_new_claim_sha256",
        "prior_new_operation_id",
        "principal_identity_sha256",
        "runtime_database_identity_sha256",
        "signing_public_key_sha256",
        "source_authority_sha256",
        "unenrolled_admission_sha256",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda approval: replace(approval, operation_id="not-a-uuid-" + SECRET_CANARY),
        lambda approval: replace(approval, operation_mode="new"),
        lambda approval: replace(approval, anchor_authority_sha256=SECRET_CANARY),
    ],
)
def test_approval_rejects_nonexact_fields_without_echoing_values(mutate: object) -> None:
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        mutate(_approval())  # type: ignore[operator]

    assert str(captured.value) == "trusted-time first enrollment approval is invalid"
    assert SECRET_CANARY not in str(captured.value)


def test_recovery_approval_requires_an_exact_prior_new_claim_binding() -> None:
    prior_new_approval = _approval()
    prior_new_claim_sha256 = hashlib.sha256(_claim_artifact_bytes(prior_new_approval)).hexdigest()
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=prior_new_claim_sha256,
    )

    assert recovery.payload()["prior_new_operation_id"] == prior_new_approval.operation_id
    assert recovery.payload()["prior_new_claim_sha256"] == prior_new_claim_sha256

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        _approval(operation_mode=TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING)
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        replace(
            prior_new_approval,
            prior_new_operation_id=prior_new_approval.operation_id,
            prior_new_claim_sha256=prior_new_claim_sha256,
        )
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        replace(recovery, prior_new_operation_id=SECRET_CANARY)
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        replace(recovery, prior_new_claim_sha256=SECRET_CANARY)


def test_operation_uuid_claim_is_consumed_even_if_mode_or_bindings_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained_names: set[str] = set()
    attempts: list[tuple[str, bytes]] = []

    def retain(_artifact_dir: Path, *, file_name: str, encoded: bytes) -> Path:
        attempts.append((file_name, encoded))
        if file_name in retained_names:
            raise launcher.TrustedTimeFirstEnrollmentClaimConsumed
        retained_names.add(file_name)
        return Path("/retained") / file_name

    monkeypatch.setattr(launcher, "_write_exclusive_retained_artifact", retain)
    approval = _approval()

    claim_sha256, claim_path, claim_encoded = launcher._retain_single_use_claim(
        approval,
        artifact_dir=Path("/retained"),
    )

    expected_name = f"trusted-time-first-enrollment-claim-{OPERATION_ID}.json"
    assert claim_path == Path("/retained") / expected_name
    assert claim_sha256 == hashlib.sha256(claim_encoded).hexdigest()
    assert launcher._canonical_json_bytes(json.loads(claim_encoded)) == claim_encoded
    assert json.loads(claim_encoded)["authority_granted"] is False
    assert json.loads(claim_encoded)["new_exposure_authorized"] is False

    distinct_prior = _approval(operation_id=ADMISSION_ID)
    recovery = _recovery_approval(
        prior_new_approval=distinct_prior,
        prior_new_claim_sha256=hashlib.sha256(_claim_artifact_bytes(distinct_prior)).hexdigest(),
    )
    changed_approvals = (
        approval,
        replace(
            recovery,
            operation_id=approval.operation_id,
        ),
        replace(approval, anchor_authority_sha256="f" * 64),
    )
    for changed in changed_approvals:
        with pytest.raises(launcher.TrustedTimeFirstEnrollmentClaimConsumed):
            launcher._retain_single_use_claim(changed, artifact_dir=Path("/retained"))

    assert [name for name, _ in attempts] == [expected_name] * 4


def test_recovery_loads_the_exact_owner_only_prior_new_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_new_approval = _approval()
    prior_new_claim = _claim_artifact_bytes(prior_new_approval)
    prior_new_claim_sha256 = hashlib.sha256(prior_new_claim).hexdigest()
    fresh_launch = replace(
        prior_new_approval.approved_launch,
        image_admission_sha256="0" * 64,
    )
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=prior_new_claim_sha256,
        approved_launch=fresh_launch,
    )
    reader = Mock(return_value=prior_new_claim)
    monkeypatch.setattr(launcher, "_read_owner_only_artifact", reader)
    artifact_dir = Path("/retained/trusted-time")

    assert (
        launcher.load_approved_prior_new_claim(
            recovery,
            artifact_dir=artifact_dir,
        )
        == prior_new_claim
    )
    reader.assert_called_once_with(
        artifact_dir,
        f"trusted-time-first-enrollment-claim-{prior_new_approval.operation_id}.json",
        maximum_bytes=launcher.MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
    )


@pytest.mark.parametrize(
    "mismatch",
    [
        "operation_id",
        "mode",
        "receipt",
        "git",
        "source_image",
        "supervisor_image",
        "authority",
    ],
)
def test_recovery_rejects_any_prior_new_claim_binding_mismatch(
    mismatch: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_new_approval = _approval()
    expected_claim = _claim_artifact_bytes(prior_new_approval)
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=hashlib.sha256(expected_claim).hexdigest(),
        approved_launch=replace(
            prior_new_approval.approved_launch,
            image_admission_sha256="0" * 64,
        ),
    )
    if mismatch == "operation_id":
        mismatched_claim = _claim_artifact_bytes(
            replace(prior_new_approval, operation_id=RECOVERY_OPERATION_ID)
        )
    elif mismatch == "mode":
        mismatched_payload = prior_new_approval.payload()
        mismatched_payload["operation_mode"] = (
            TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING.value
        )
        mismatched_claim = _claim_artifact_bytes_from_approval_payload(mismatched_payload)
    elif mismatch == "receipt":
        mismatched_claim = _claim_artifact_bytes(
            replace(prior_new_approval, unenrolled_admission_sha256="e" * 64)
        )
    elif mismatch == "git":
        mismatched_claim = _claim_artifact_bytes(
            replace(
                prior_new_approval,
                approved_launch=replace(
                    prior_new_approval.approved_launch,
                    git_revision="b" * 40,
                ),
            )
        )
    elif mismatch == "source_image":
        mismatched_claim = _claim_artifact_bytes(
            replace(
                prior_new_approval,
                approved_launch=replace(
                    prior_new_approval.approved_launch,
                    source_image_id="sha256:" + "4" * 64,
                ),
            )
        )
    elif mismatch == "supervisor_image":
        mismatched_claim = _claim_artifact_bytes(
            replace(
                prior_new_approval,
                approved_launch=replace(
                    prior_new_approval.approved_launch,
                    supervisor_image_id="sha256:" + "5" * 64,
                ),
            )
        )
    else:
        mismatched_claim = _claim_artifact_bytes(
            replace(prior_new_approval, anchor_authority_sha256="f" * 64)
        )
    recovery = replace(
        recovery,
        prior_new_claim_sha256=hashlib.sha256(mismatched_claim).hexdigest(),
    )
    monkeypatch.setattr(
        launcher,
        "_read_owner_only_artifact",
        Mock(return_value=mismatched_claim),
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        launcher.load_approved_prior_new_claim(recovery)


def test_recovery_rejects_prior_claim_image_admission_that_differs_from_receipt() -> None:
    prior_new_approval = _approval()
    prior_new_claim = _claim_artifact_bytes(prior_new_approval)
    receipt_payload = json.loads(_unenrolled_receipt())
    receipt_payload["image_admission_sha256"] = "0" * 64
    mismatched_receipt = launcher._canonical_json_bytes(receipt_payload)
    recovery = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=hashlib.sha256(prior_new_claim).hexdigest(),
        approved_launch=replace(
            prior_new_approval.approved_launch,
            image_admission_sha256="f" * 64,
        ),
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="prior claim differs from receipt",
    ):
        launcher._require_prior_claim_receipt_binding(
            approval=recovery,
            prior_claim_encoded=prior_new_claim,
            receipt_encoded=mismatched_receipt,
        )


def test_owner_only_artifact_reader_requires_exact_metadata(
    tmp_path: Path,
) -> None:
    ignored_root = (tmp_path / "artifacts").resolve()
    artifact_dir = ignored_root / "trusted-time"
    ignored_root.mkdir(mode=0o700)
    artifact_dir.mkdir(mode=0o700)
    ignored_root.chmod(0o700)
    artifact_dir.chmod(0o700)
    artifact = artifact_dir / "receipt.json"
    artifact.write_bytes(b'{"status":"admitted"}\n')
    artifact.chmod(0o600)

    assert (
        launcher._read_owner_only_artifact(
            artifact_dir,
            artifact.name,
            maximum_bytes=100,
            ignored_root=ignored_root,
        )
        == artifact.read_bytes()
    )
    metadata = artifact.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600

    artifact.chmod(0o640)
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        launcher._read_owner_only_artifact(
            artifact_dir,
            artifact.name,
            maximum_bytes=100,
            ignored_root=ignored_root,
        )

    assert str(captured.value) == "trusted-time first enrollment artifact is unavailable"


def test_unenrolled_receipt_is_canonical_and_bound_to_the_exact_approved_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = _unenrolled_receipt()
    approval = _approval(
        unenrolled_admission_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    reader = Mock(return_value=encoded)
    monkeypatch.setattr(launcher, "_read_owner_only_artifact", reader)
    artifact_dir = Path("/retained/trusted-time")

    assert (
        launcher.load_approved_unenrolled_admission(
            approval,
            artifact_dir=artifact_dir,
        )
        == encoded
    )
    reader.assert_called_once_with(
        artifact_dir,
        f"trusted-time-unenrolled-launch-admission-{approval.unenrolled_admission_sha256}.json",
        maximum_bytes=launcher.MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES,
    )


def test_unenrolled_receipt_rejects_content_tamper_noncanonical_bytes_and_tuple_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = _unenrolled_receipt()
    exact_approval = _approval(
        unenrolled_admission_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    monkeypatch.setattr(
        launcher,
        "_read_owner_only_artifact",
        Mock(return_value=encoded.replace(b'"admitted"', b'"rejected"')),
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as changed:
        launcher.load_approved_unenrolled_admission(exact_approval)
    assert str(changed.value) == "trusted-time first enrollment unenrolled admission changed"

    payload = json.loads(encoded)
    noncanonical = (json.dumps(payload, indent=2) + "\n").encode("ascii")
    noncanonical_approval = replace(
        exact_approval,
        unenrolled_admission_sha256=hashlib.sha256(noncanonical).hexdigest(),
    )
    monkeypatch.setattr(
        launcher,
        "_read_owner_only_artifact",
        Mock(return_value=noncanonical),
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as formatting:
        launcher.load_approved_unenrolled_admission(noncanonical_approval)
    assert (
        str(formatting.value)
        == "trusted-time first enrollment unenrolled admission differs from approval"
    )

    payload["source_image_id"] = "sha256:" + "3" * 64
    drifted = launcher._canonical_json_bytes(payload)
    drifted_approval = replace(
        exact_approval,
        unenrolled_admission_sha256=hashlib.sha256(drifted).hexdigest(),
    )
    monkeypatch.setattr(
        launcher,
        "_read_owner_only_artifact",
        Mock(return_value=drifted),
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as tuple_drift:
        launcher.load_approved_unenrolled_admission(drifted_approval)
    assert (
        str(tuple_drift.value)
        == "trusted-time first enrollment unenrolled admission differs from approval"
    )


def test_recovery_pairs_the_original_receipt_with_a_fresh_same_image_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = _unenrolled_receipt()
    prior_new_approval = _approval(
        unenrolled_admission_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    prior_new_claim_sha256 = hashlib.sha256(_claim_artifact_bytes(prior_new_approval)).hexdigest()
    fresh_launch = replace(
        _approved_launch(),
        image_admission_sha256="0" * 64,
    )
    recovery_approval = _recovery_approval(
        prior_new_approval=prior_new_approval,
        prior_new_claim_sha256=prior_new_claim_sha256,
        approved_launch=fresh_launch,
    )
    monkeypatch.setattr(
        launcher,
        "_read_owner_only_artifact",
        Mock(return_value=encoded),
    )

    assert launcher.load_approved_unenrolled_admission(recovery_approval) == encoded

    new_approval = replace(
        recovery_approval,
        operation_mode=TrustedTimeFirstEnrollmentOperationMode.NEW,
        prior_new_operation_id=None,
        prior_new_claim_sha256=None,
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as stale_new:
        launcher.load_approved_unenrolled_admission(new_approval)
    assert (
        str(stale_new.value)
        == "trusted-time first enrollment unenrolled admission differs from approval"
    )

    changed_image_recovery = replace(
        recovery_approval,
        approved_launch=replace(
            fresh_launch,
            source_image_id="sha256:" + "4" * 64,
        ),
    )
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as changed_image:
        launcher.load_approved_unenrolled_admission(changed_image_recovery)
    assert (
        str(changed_image.value)
        == "trusted-time first enrollment unenrolled admission differs from approval"
    )


def test_image_admission_reserve_accepts_the_exact_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = _image_admission_snapshot()
    maximum_release_age = (
        launcher.IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
        - launcher.FIRST_ENROLLMENT_MINIMUM_IMAGE_ADMISSION_RESERVE_SECONDS
    )
    monkeypatch.setattr(
        launcher.time,
        "monotonic_ns",
        lambda: admission[12] + maximum_release_age * 1_000_000_000,
    )

    launcher._require_image_admission_reserve(admission)


@pytest.mark.parametrize("observed_offset_ns", [-1, 600_000_000_000 + 1])
def test_image_admission_reserve_rejects_clock_regression_or_insufficient_reserve(
    observed_offset_ns: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = _image_admission_snapshot()
    monkeypatch.setattr(
        launcher.time,
        "monotonic_ns",
        lambda: admission[12] + observed_offset_ns,
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        launcher._require_image_admission_reserve(admission)

    assert (
        str(captured.value) == "trusted-time first enrollment image admission lacks release reserve"
    )


@pytest.mark.parametrize(
    ("operation_mode", "release_target"),
    [
        (
            TrustedTimeFirstEnrollmentOperationMode.NEW,
            "first-enrollment-release",
        ),
        (
            TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
            "first-enrollment-recovery-release",
        ),
    ],
)
def test_release_enrollment_container_uses_fixed_native_launcher_target(
    operation_mode: TrustedTimeFirstEnrollmentOperationMode,
    release_target: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {"DOCKER_HOST": "unix:///private/tmp/approved-docker.sock"}
    expected_argv = (
        "docker",
        "container",
        "exec",
        "--user",
        "10001:10001",
        CONTAINER_ID,
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        release_target,
    )
    docker = Mock(return_value=_process_result(expected_argv, 0, "", ""))
    monkeypatch.setattr(launcher, "_run_docker", docker)

    launcher._release_enrollment_container(
        container_id=CONTAINER_ID,
        operation_mode=operation_mode,
        environment=environment,
    )

    docker.assert_called_once_with(
        expected_argv,
        environment=environment,
        timeout_seconds=10,
    )


def test_terminal_success_and_fatal_evidence_are_closed_and_secretless() -> None:
    approval = _approval()
    success_payload = _terminal_payload(approval)
    fatal_payload = _fatal_terminal_payload(approval)

    success = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
        exit_code=0,
        payload=success_payload,
    )
    fatal = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
        exit_code=2,
        payload=fatal_payload,
    )

    assert success.confirmed is True
    assert fatal.confirmed is False
    assert set(success.payload) == launcher._TERMINAL_FIELDS
    assert all(success.payload[field] is False for field in launcher._AUTHORITY_FIELDS)
    assert all(fatal.payload[field] is False for field in launcher._AUTHORITY_FIELDS)
    assert SECRET_CANARY.encode() not in launcher._canonical_json_bytes(success.payload)

    secret_bearing = dict(success_payload)
    secret_bearing["raw_secret"] = SECRET_CANARY
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=0,
            payload=secret_bearing,
        )
    assert SECRET_CANARY not in str(captured.value)

    boolean_sequence = dict(success_payload)
    boolean_sequence["anchor_sequence"] = True
    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=0,
            payload=boolean_sequence,
        )


@pytest.mark.parametrize(
    ("observed_mode", "disposition"),
    [
        (TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING, "new_intent_completed"),
        (TrustedTimeFirstEnrollmentOperationMode.NEW, "pending_intent_recovered"),
    ],
)
def test_terminal_observation_binds_mode_and_disposition_without_docker(
    observed_mode: TrustedTimeFirstEnrollmentOperationMode,
    disposition: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _approval()
    payload = _terminal_payload(
        approval,
        operation_mode=observed_mode,
        disposition=disposition,
    )
    encoded = launcher._canonical_json_bytes(payload)
    monkeypatch.setattr(
        launcher,
        "_inspect_container",
        Mock(return_value=_terminal_inspection(exit_code=0)),
    )
    docker = Mock(
        return_value=_process_result(
            args=("docker",),
            returncode=0,
            stdout=encoded.decode("ascii"),
            stderr="",
        )
    )
    monkeypatch.setattr(launcher, "_run_docker", docker)
    monkeypatch.setattr(launcher.time, "monotonic", lambda: 10.0)

    with pytest.raises(launcher.TrustedTimeFirstEnrollmentPossibleMutation) as captured:
        launcher._observe_enrollment_terminal(
            container_id=CONTAINER_ID,
            approval=approval,
            environment={},
        )

    assert str(captured.value) == "trusted-time first enrollment terminal differs from approval"
    docker.assert_called_once()


def test_terminal_observation_accepts_one_exact_bound_success_without_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _approval()
    encoded = launcher._canonical_json_bytes(_terminal_payload(approval))
    monkeypatch.setattr(
        launcher,
        "_inspect_container",
        Mock(return_value=_terminal_inspection(exit_code=0)),
    )
    monkeypatch.setattr(
        launcher,
        "_run_docker",
        Mock(
            return_value=_process_result(
                args=("docker",),
                returncode=0,
                stdout=encoded.decode("ascii"),
                stderr="",
            )
        ),
    )
    monkeypatch.setattr(launcher.time, "monotonic", lambda: 10.0)

    evidence = launcher._observe_enrollment_terminal(
        container_id=CONTAINER_ID,
        approval=approval,
        environment={},
    )

    assert evidence.confirmed is True
    assert evidence.payload["completion_disposition"] == "new_intent_completed"


@pytest.mark.parametrize(
    ("evidence_kind", "gate_override", "expected"),
    [
        ("success", {}, ("confirmed", "first_enrollment_confirmed", True)),
        (
            "success",
            {"final_image_admission_fresh": False},
            (
                "fatal",
                "first_enrollment_completed_postconditions_unconfirmed",
                False,
            ),
        ),
        (
            "fatal",
            {},
            ("fatal", "provider_unavailable_before_commit", False),
        ),
        (
            "fatal",
            {"topology_removed": False},
            ("fatal", "first_enrollment_recovery_required", False),
        ),
        (
            "completed",
            {"single_use_claim_retained": False},
            (
                "fatal",
                "first_enrollment_completed_postconditions_unconfirmed",
                False,
            ),
        ),
        (
            "none",
            {},
            ("fatal", "first_enrollment_recovery_required", False),
        ),
    ],
)
def test_outcome_classification_is_fail_closed_across_terminal_and_gate_states(
    evidence_kind: str,
    gate_override: dict[str, bool],
    expected: tuple[str, str, bool],
) -> None:
    approval = _approval()
    evidence: launcher.TrustedTimeFirstEnrollmentTerminalEvidence | None
    if evidence_kind == "success":
        evidence = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=0,
            payload=_terminal_payload(approval),
        )
    elif evidence_kind == "fatal":
        evidence = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=2,
            payload=_fatal_terminal_payload(approval),
        )
    elif evidence_kind == "completed":
        evidence = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=2,
            payload=_completed_unconfirmed_payload(approval),
        )
    else:
        evidence = None

    assert (
        launcher._outcome_reason(
            terminal_evidence=evidence,
            gates=_all_gates(**gate_override),
        )
        == expected
    )


def test_host_outcome_retains_exact_gates_canonical_evidence_and_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _approval()
    terminal = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
        exit_code=0,
        payload=_terminal_payload(approval),
    )
    retained: dict[str, object] = {}

    def write(artifact_dir: Path, *, file_name: str, encoded: bytes) -> Path:
        retained.update(file_name=file_name, encoded=encoded)
        return artifact_dir / file_name

    monkeypatch.setattr(launcher, "_write_exclusive_retained_artifact", write)
    outcome = launcher._retain_host_outcome(
        approval=approval,
        claim_sha256="f" * 64,
        terminal_evidence=terminal,
        gates=_all_gates(),
        artifact_dir=Path("/retained/trusted-time"),
    )

    payload = json.loads(outcome.encoded)
    assert outcome.confirmed is True
    assert outcome.encoded == retained["encoded"]
    assert launcher._canonical_json_bytes(payload) == outcome.encoded
    assert payload["gates"] == _all_gates()
    assert payload["authority_granted"] is False
    assert payload["new_exposure_authorized"] is False
    assert payload["database_secret_disclosed"] is False
    assert payload["runtime_terminal"] == _terminal_payload(approval)
    assert retained["file_name"] == (
        f"trusted-time-first-enrollment-outcome-{hashlib.sha256(outcome.encoded).hexdigest()}.json"
    )


def test_confirmed_writer_bytes_round_trip_through_post_enrollment_codec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _approval()
    claim_encoded = launcher._canonical_json_bytes(launcher._claim_payload(approval))
    claim_sha256 = hashlib.sha256(claim_encoded).hexdigest()
    terminal = launcher.TrustedTimeFirstEnrollmentTerminalEvidence(
        exit_code=0,
        payload=_terminal_payload(approval),
    )
    monkeypatch.setattr(
        launcher,
        "_write_exclusive_retained_artifact",
        lambda artifact_dir, *, file_name, encoded: artifact_dir / file_name,
    )
    outcome = launcher._retain_host_outcome(
        approval=approval,
        claim_sha256=claim_sha256,
        terminal_evidence=terminal,
        gates=_all_gates(),
        artifact_dir=Path("/retained/trusted-time"),
    )

    decoded = decode_confirmed_first_enrollment(
        claim_encoded=claim_encoded,
        outcome_encoded=outcome.encoded,
        expected_operation_id=approval.operation_id,
        expected_claim_sha256=claim_sha256,
        expected_outcome_sha256=hashlib.sha256(outcome.encoded).hexdigest(),
    )

    assert decoded.operation_id == approval.operation_id
    assert decoded.approval_sha256 == approval.approval_sha256
    assert decoded.sequence_one.remote_namespace_sha256 == "8" * 64


def test_host_outcome_retention_failure_has_dedicated_secretless_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        launcher,
        "_write_exclusive_retained_artifact",
        Mock(
            side_effect=TrustedTimeSupervisorConfigurationError(
                "retention failure " + SECRET_CANARY
            )
        ),
    )

    with pytest.raises(launcher.TrustedTimeFirstEnrollmentOutcomeRetentionUnconfirmed) as captured:
        launcher._retain_host_outcome(
            approval=_approval(),
            claim_sha256="f" * 64,
            terminal_evidence=None,
            gates=_all_gates(terminal_evidence_qualified=False),
            artifact_dir=Path("/retained/trusted-time"),
        )

    assert str(captured.value) == "trusted-time first enrollment outcome retention is unconfirmed"
    assert SECRET_CANARY not in str(captured.value)


def test_cli_emits_dedicated_outcome_retention_failure_without_opening_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(**_kwargs: object) -> launcher.TrustedTimeFirstEnrollmentHostOutcome:
        raise launcher.TrustedTimeFirstEnrollmentOutcomeRetentionUnconfirmed(SECRET_CANARY)

    monkeypatch.setattr(sys, "argv", _cli_arguments())
    monkeypatch.setattr(launcher, "run_first_enrollment", fail)

    with pytest.raises(SystemExit) as captured:
        launcher.main()

    assert captured.value.code == 2
    emitted = capsys.readouterr().out.encode("ascii")
    assert emitted == launcher._safe_pre_release_payload(
        "first_enrollment_outcome_retention_unconfirmed"
    )
    assert SECRET_CANARY.encode() not in emitted


def test_cli_binds_recovery_to_the_exact_prior_new_claim(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}
    prior_claim_sha256 = "e" * 64
    outcome = launcher.TrustedTimeFirstEnrollmentHostOutcome(
        encoded=b'{"status":"confirmed"}\n',
        artifact_path=Path("/retained/outcome.json"),
        confirmed=True,
    )

    def run(**kwargs: object) -> launcher.TrustedTimeFirstEnrollmentHostOutcome:
        observed.update(kwargs)
        return outcome

    monkeypatch.setattr(
        sys,
        "argv",
        _cli_arguments(
            recover_pending=True,
            prior_new_operation_id=OPERATION_ID,
            prior_new_claim_sha256=prior_claim_sha256,
        ),
    )
    monkeypatch.setattr(launcher, "run_first_enrollment", run)

    launcher.main()

    approval = observed["approval"]
    assert isinstance(approval, launcher.TrustedTimeFirstEnrollmentApproval)
    assert approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
    assert approval.prior_new_operation_id == OPERATION_ID
    assert approval.prior_new_claim_sha256 == prior_claim_sha256
    assert capsys.readouterr().out.encode("ascii") == outcome.encoded


def test_global_lock_wraps_the_entire_launcher_without_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    approval = _approval()
    expected = launcher.TrustedTimeFirstEnrollmentHostOutcome(
        encoded=b'{"status":"confirmed"}\n',
        artifact_path=Path("/retained/outcome.json"),
        confirmed=True,
    )

    def acquire() -> int:
        events.append("acquire")
        return 42

    def run(**kwargs: object) -> launcher.TrustedTimeFirstEnrollmentHostOutcome:
        events.append(("run", kwargs))
        return expected

    def release(descriptor: int) -> None:
        events.append(("release", descriptor))

    monkeypatch.setattr(launcher, "_acquire_trusted_time_launch_lock", acquire)
    monkeypatch.setattr(launcher, "_run_first_enrollment_under_lock", run)
    monkeypatch.setattr(launcher, "_release_trusted_time_launch_lock", release)
    env_file = Path("/owner/trusted-time-launch.env")
    image_admission = Path("/retained/image-admission.json")
    artifact_dir = Path("/retained/trusted-time")

    assert (
        launcher.run_first_enrollment(
            env_file=env_file,
            approval=approval,
            image_admission_artifact=image_admission,
            artifact_dir=artifact_dir,
        )
        is expected
    )
    assert events == [
        "acquire",
        (
            "run",
            {
                "env_file": env_file,
                "approval": approval,
                "image_admission_artifact": image_admission,
                "artifact_dir": artifact_dir,
            },
        ),
        ("release", 42),
    ]


def test_global_lock_is_released_when_the_launcher_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = Mock()
    failure = TrustedTimeSupervisorConfigurationError(SECRET_CANARY)
    monkeypatch.setattr(launcher, "_acquire_trusted_time_launch_lock", lambda: 77)
    monkeypatch.setattr(
        launcher,
        "_run_first_enrollment_under_lock",
        Mock(side_effect=failure),
    )
    monkeypatch.setattr(launcher, "_release_trusted_time_launch_lock", release)

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        launcher.run_first_enrollment(
            env_file=Path("/owner/trusted-time-launch.env"),
            approval=_approval(),
        )

    assert captured.value is failure
    release.assert_called_once_with(77)


def test_success_is_not_returned_when_global_lock_release_is_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = launcher.TrustedTimeFirstEnrollmentHostOutcome(
        encoded=b'{"status":"confirmed"}\n',
        artifact_path=Path("/retained/outcome.json"),
        confirmed=True,
    )
    monkeypatch.setattr(launcher, "_acquire_trusted_time_launch_lock", lambda: 88)
    monkeypatch.setattr(
        launcher,
        "_run_first_enrollment_under_lock",
        Mock(return_value=expected),
    )
    monkeypatch.setattr(
        launcher,
        "_release_trusted_time_launch_lock",
        Mock(side_effect=TrustedTimeSupervisorConfigurationError("lock failure " + SECRET_CANARY)),
    )

    with pytest.raises(launcher.TrustedTimeFirstEnrollmentLockReleaseUnconfirmed) as captured:
        launcher.run_first_enrollment(
            env_file=Path("/owner/trusted-time-launch.env"),
            approval=_approval(),
        )

    assert str(captured.value) == "trusted-time first enrollment launch lock release is unconfirmed"
    assert SECRET_CANARY not in str(captured.value)
