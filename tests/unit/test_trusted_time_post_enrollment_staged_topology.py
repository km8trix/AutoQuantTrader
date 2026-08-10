from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Literal, cast
from unittest.mock import patch

import pytest

from apps.trusted_time_supervisor.main import DATABASE_SECRET_CONSUMED_BYTES
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts import trusted_time_post_enrollment_start as post_enrollment_start_script
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
    DATABASE_SECRET_CONSUMED_PATH,
    DATABASE_SECRET_CONSUMED_SHA256,
    DATABASE_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
    POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS,
    TrustedTimePostEnrollmentAbsentPathCandidate,
    TrustedTimePostEnrollmentConsumedMarkerCandidate,
    TrustedTimePostEnrollmentStagedTopologyRejected,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    validate_post_enrollment_start_staged_unreleased_topology,
)
from scripts.trusted_time_post_enrollment_topology import (
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    validate_post_enrollment_start_created_topology,
)

SOURCE_CONTAINER_ID = "a" * 64
SUPERVISOR_CONTAINER_ID = "b" * 64
OTHER_CONTAINER_ID = "c" * 64
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
PROJECT_NAME = "autoquanttrader-trusted-time"
ZERO_DOCKER_TIMESTAMP = "0001-01-01T00:00:00Z"
STARTED_AT = "2026-08-09T12:34:56.123456789Z"
OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"


class _EqualString(str):
    pass


SOURCE_COMMAND = [
    "-x",
    "-d",
    "-U",
    "-f",
    "/etc/autoquant/trusted-time/chrony.conf",
]
SUPERVISOR_COMMAND = ["autoquant-trusted-time-supervisor"]
STOP_SIGNAL = "SIGTERM"
MASKED_PATHS = [
    "/proc/asound",
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
]
READONLY_PATHS = [
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
]

_SUPERVISOR_RUNTIME_ENVIRONMENT = [
    "AQT_TRUSTED_TIME_AUTHORITY_PATH=/etc/autoquant/trusted-time/source-authority.json",
    "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH=/etc/autoquant/trusted-time/chrony.conf",
    f"AQT_TRUSTED_TIME_DATABASE_URL_FILE={DATABASE_SECRET_RUNTIME_PATH}",
    f"AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH={HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH}",
    f"AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE={HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH}",
    f"AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE={HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH}",
]


def _identities() -> TrustedTimeFirstEnrollmentIdentities:
    return TrustedTimeFirstEnrollmentIdentities(
        anchor_authority_sha256="1" * 64,
        anchor_project_identity_sha256="2" * 64,
        bucket_identity_sha256="3" * 64,
        deployment_identity_sha256="4" * 64,
        host_identity_sha256="5" * 64,
        principal_identity_sha256="6" * 64,
        runtime_database_identity_sha256="7" * 64,
        signing_public_key_sha256="8" * 64,
        source_authority_sha256="9" * 64,
    )


def _sequence_one() -> TrustedTimeSequenceOneEvidence:
    return TrustedTimeSequenceOneEvidence(
        completion_disposition="new_intent_completed",
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        anchor_intent_semantic_sha256="a" * 64,
        candidate_remote_readback_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        current_anchor_sha256="b" * 64,
        current_host_head_sha256="d" * 64,
        receipt_semantic_sha256="e" * 64,
        remote_namespace_sha256="f" * 64,
    )


def _confirmed_enrollment() -> TrustedTimeConfirmedFirstEnrollment:
    return TrustedTimeConfirmedFirstEnrollment(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="0" * 64,
        claim_sha256="1" * 64,
        outcome_sha256="2" * 64,
        unenrolled_admission_sha256="3" * 64,
        enrollment_launch=TrustedTimeImmutableLaunchEvidence(
            git_revision="a" * 40,
            image_admission_sha256="4" * 64,
            source_image_id="sha256:" + "5" * 64,
            supervisor_image_id="sha256:" + "6" * 64,
        ),
        identities=_identities(),
        sequence_one=_sequence_one(),
    )


def _approval() -> TrustedTimePostEnrollmentStartApproval:
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=OPERATION_ID,
        review=build_post_enrollment_start_review(
            confirmed_enrollment=_confirmed_enrollment(),
            proposed_launch=TrustedTimeImmutableLaunchEvidence(
                git_revision="f" * 40,
                image_admission_sha256="7" * 64,
                source_image_id=SOURCE_IMAGE_ID,
                supervisor_image_id=SUPERVISOR_IMAGE_ID,
            ),
        ),
    )


def _approved_launch() -> TrustedTimeApprovedLaunch:
    proposed = _approval().proposed_launch
    return TrustedTimeApprovedLaunch(
        git_revision=proposed.git_revision,
        image_admission_sha256=proposed.image_admission_sha256,
        source_image_id=proposed.source_image_id,
        supervisor_image_id=proposed.supervisor_image_id,
    )


def _daemon_identity() -> LocalDockerDaemonIdentity:
    return LocalDockerDaemonIdentity(
        context_name="desktop-linux",
        endpoint="unix:///local/docker.sock",
        daemon_id="LOCAL:DAEMON:1",
    )


def _volume_identities() -> TrustedTimeVolumeIdentities:
    return TrustedTimeVolumeIdentities(
        socket_sha256="a" * 64,
        state_sha256="b" * 64,
    )


def _staged_paths(root: Path) -> dict[str, Path]:
    return {
        "database": root / ".database-secret-" / "database-url",
        "authority": root / ".head-anchor-authority-" / "head-anchor-authority.json",
        "auth": root / ".head-anchor-auth-" / "head-anchor-auth",
        "signing": root / ".head-anchor-signing-key-" / "head-anchor-signing-key",
    }


def _image_configuration(role: Literal["source", "supervisor"]) -> dict[str, object]:
    if role == "source":
        return {
            "Cmd": SOURCE_COMMAND.copy(),
            "Entrypoint": ["/usr/sbin/chronyd"],
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"],
            "ExposedPorts": None,
            "StopSignal": STOP_SIGNAL,
            "User": "10001:10001",
            "WorkingDir": "",
        }
    return {
        "Cmd": SUPERVISOR_COMMAND.copy(),
        "Entrypoint": None,
        "Env": ["PATH=/opt/venv/bin:/usr/local/bin:/usr/bin"],
        "ExposedPorts": None,
        "StopSignal": STOP_SIGNAL,
        "User": "10001:10001",
        "WorkingDir": "/workspace",
    }


def _state(
    role: Literal["source", "supervisor"],
    *,
    running: bool,
) -> dict[str, object]:
    result: dict[str, object] = {
        "Dead": False,
        "Error": "",
        "ExitCode": 0,
        "FinishedAt": ZERO_DOCKER_TIMESTAMP,
        "OOMKilled": False,
        "Paused": False,
        "Pid": (101 if role == "source" else 102) if running else 0,
        "Restarting": False,
        "Running": running,
        "StartedAt": STARTED_AT if running else ZERO_DOCKER_TIMESTAMP,
        "Status": "running" if running else "created",
    }
    if running and role == "source":
        result["Health"] = {
            "FailingStreak": 0,
            "Log": [
                {
                    "End": "2026-08-09T12:35:01.000000000Z",
                    "ExitCode": 0,
                    "Output": "healthy\n",
                    "Start": "2026-08-09T12:35:00.000000000Z",
                }
            ],
            "Status": "healthy",
        }
    return result


def _labels(role: Literal["source", "supervisor"]) -> dict[str, str]:
    return {
        "com.docker.compose.container-number": "1",
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.project": PROJECT_NAME,
        "com.docker.compose.service": (
            "chrony-nts" if role == "source" else "trusted-time-supervisor"
        ),
    }


def _volume_request(*, source: str, target: str, nocopy: bool) -> dict[str, object]:
    return {
        "ReadOnly": False,
        "Source": source,
        "Target": target,
        "Type": "volume",
        "VolumeOptions": {"NoCopy": nocopy},
    }


def _bind_request(*, source: Path, target: str) -> dict[str, object]:
    return {
        "ReadOnly": True,
        "Source": str(source),
        "Target": target,
        "Type": "bind",
    }


def _runtime_volume(*, name: str, destination: str) -> dict[str, object]:
    return {
        "Destination": destination,
        "Name": name,
        "RW": True,
        "Type": "volume",
    }


def _runtime_bind(*, source: Path, destination: str) -> dict[str, object]:
    return {
        "Destination": destination,
        "RW": False,
        "Source": str(source),
        "Type": "bind",
    }


def _container_inspection(
    *,
    role: Literal["source", "supervisor"],
    container_id: str,
    image_id: str,
    staged_paths: dict[str, Path],
    running: bool,
) -> list[dict[str, object]]:
    source = role == "source"
    image_configuration = _image_configuration(role)
    runtime_environment = cast(list[str], image_configuration["Env"]).copy()
    if not source:
        runtime_environment.extend(_SUPERVISOR_RUNTIME_ENVIRONMENT)

    socket_request = _volume_request(
        source=COMPOSE_SOCKET_VOLUME_NAME,
        target="/run/chrony",
        nocopy=True,
    )
    input_requests = [
        _bind_request(source=staged_paths["database"], target=DATABASE_SECRET_RUNTIME_PATH),
        _bind_request(
            source=staged_paths["authority"],
            target=HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
        ),
        _bind_request(
            source=staged_paths["auth"],
            target=HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
        ),
        _bind_request(
            source=staged_paths["signing"],
            target=HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
        ),
    ]
    runtime_inputs = [
        _runtime_bind(
            source=staged_paths["database"],
            destination=DATABASE_SECRET_RUNTIME_PATH,
        ),
        _runtime_bind(
            source=staged_paths["authority"],
            destination=HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
        ),
        _runtime_bind(
            source=staged_paths["auth"],
            destination=HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
        ),
        _runtime_bind(
            source=staged_paths["signing"],
            destination=HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
        ),
    ]
    healthcheck: object = None
    if source:
        healthcheck = {
            "Interval": 2_000_000_000,
            "Retries": 15,
            "StartPeriod": 2_000_000_000,
            "Test": [
                "CMD",
                "/usr/bin/chronyc",
                "-h",
                "/run/chrony/chronyd.sock",
                "activity",
            ],
            "Timeout": 1_000_000_000,
        }

    return [
        {
            "Args": SOURCE_COMMAND.copy() if source else [],
            "Config": {
                **image_configuration,
                "Env": runtime_environment,
                "Healthcheck": healthcheck,
                "Image": image_id,
                "Labels": _labels(role),
                "NetworkDisabled": False,
            },
            "HostConfig": {
                "AutoRemove": False,
                "Binds": ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw"] if source else None),
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "Cgroup": "",
                "CgroupnsMode": "private",
                "DeviceCgroupRules": None,
                "DeviceRequests": None,
                "Devices": None,
                "Dns": None,
                "DnsOptions": None,
                "DnsSearch": None,
                "ExtraHosts": None,
                "GroupAdd": None,
                "Init": True,
                "IpcMode": "private",
                "Links": None,
                "LogConfig": {"Config": {}, "Type": "json-file"},
                "MaskedPaths": MASKED_PATHS.copy(),
                "Memory": 67_108_864 if source else 268_435_456,
                "Mounts": [socket_request] if source else [socket_request, *input_requests],
                "NanoCpus": 250_000_000 if source else 500_000_000,
                "NetworkMode": COMPOSE_NETWORK_NAME,
                "OomKillDisable": False,
                "PidMode": "",
                "PidsLimit": 32 if source else 64,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyPaths": READONLY_PATHS.copy(),
                "ReadonlyRootfs": True,
                "RestartPolicy": {
                    "MaximumRetryCount": 0,
                    "Name": "unless-stopped" if source else "no",
                },
                "SecurityOpt": ["no-new-privileges:true"],
                "Sysctls": {},
                "Tmpfs": {
                    "/tmp": (
                        "rw,noexec,nosuid,nodev,"
                        f"size={'8m' if source else '16m'},"
                        "uid=10001,gid=10001,mode=0700"
                    )
                },
                "UTSMode": "",
                "UsernsMode": "",
                "VolumesFrom": None,
            },
            "Id": container_id,
            "Image": image_id,
            "Mounts": [
                _runtime_volume(
                    name=COMPOSE_SOCKET_VOLUME_NAME,
                    destination="/run/chrony",
                ),
                *(
                    [
                        _runtime_volume(
                            name=COMPOSE_STATE_VOLUME_NAME,
                            destination="/var/lib/chrony",
                        )
                    ]
                    if source
                    else runtime_inputs
                ),
            ],
            "NetworkSettings": {"Networks": {COMPOSE_NETWORK_NAME: {}}},
            "Path": "/usr/sbin/chronyd" if source else "autoquant-trusted-time-supervisor",
            "RestartCount": 0,
            "State": _state(role, running=running),
        }
    ]


def _marker_candidate(**changes: object) -> TrustedTimePostEnrollmentConsumedMarkerCandidate:
    values: dict[str, object] = {
        "path": DATABASE_SECRET_CONSUMED_PATH,
        "byte_sha256": DATABASE_SECRET_CONSUMED_SHA256,
        "size": len(DATABASE_SECRET_CONSUMED_BYTES),
        "owner_uid": 10_001,
        "owner_gid": 10_001,
        "mode": 0o400,
        "link_count": 1,
        "regular": True,
        "device": 4,
        "inode": 5,
        "modified_time_ns": 6,
        "changed_time_ns": 7,
    }
    values.update(changes)
    return TrustedTimePostEnrollmentConsumedMarkerCandidate(**values)  # type: ignore[arg-type]


def _absence_candidates(
    paths: list[str],
) -> tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...]:
    return tuple(TrustedTimePostEnrollmentAbsentPathCandidate(path=path) for path in paths)


def _valid_inputs(root: Path) -> dict[str, object]:
    paths = _staged_paths(root)
    created_source = _container_inspection(
        role="source",
        container_id=SOURCE_CONTAINER_ID,
        image_id=SOURCE_IMAGE_ID,
        staged_paths=paths,
        running=False,
    )
    created_supervisor = _container_inspection(
        role="supervisor",
        container_id=SUPERVISOR_CONTAINER_ID,
        image_id=SUPERVISOR_IMAGE_ID,
        staged_paths=paths,
        running=False,
    )
    created = validate_post_enrollment_start_created_topology(
        approval=_approval(),
        approved_launch=_approved_launch(),
        daemon_identity_before=_daemon_identity(),
        daemon_identity_after=_daemon_identity(),
        volume_identities_before=_volume_identities(),
        volume_identities_after=_volume_identities(),
        project_container_ids_before=(SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID),
        project_container_ids_after=(SUPERVISOR_CONTAINER_ID, SOURCE_CONTAINER_ID),
        container_inspections={
            SOURCE_CONTAINER_ID: created_source,
            SUPERVISOR_CONTAINER_ID: created_supervisor,
        },
        source_image_configuration=_image_configuration("source"),
        supervisor_image_configuration=_image_configuration("supervisor"),
        expected_database_secret_file=paths["database"],
        expected_head_anchor_authority_file=paths["authority"],
        expected_head_anchor_auth_secret_file=paths["auth"],
        expected_head_anchor_signing_key_secret_file=paths["signing"],
    )
    release_paths = [
        POST_ENROLLMENT_START_RELEASE_PATH,
        POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    ]
    staged_path_strings = [str(path) for path in paths.values()]
    return {
        "approval": _approval(),
        "approved_launch": _approved_launch(),
        "created_topology": created,
        "daemon_identity_before": _daemon_identity(),
        "daemon_identity_after": _daemon_identity(),
        "volume_identities_before": _volume_identities(),
        "volume_identities_after": _volume_identities(),
        "project_container_ids_before": (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID),
        "project_container_ids_after": (SUPERVISOR_CONTAINER_ID, SOURCE_CONTAINER_ID),
        "container_inspections": {
            SUPERVISOR_CONTAINER_ID: _container_inspection(
                role="supervisor",
                container_id=SUPERVISOR_CONTAINER_ID,
                image_id=SUPERVISOR_IMAGE_ID,
                staged_paths=paths,
                running=True,
            ),
            SOURCE_CONTAINER_ID: _container_inspection(
                role="source",
                container_id=SOURCE_CONTAINER_ID,
                image_id=SOURCE_IMAGE_ID,
                staged_paths=paths,
                running=True,
            ),
        },
        "source_image_configuration": _image_configuration("source"),
        "supervisor_image_configuration": _image_configuration("supervisor"),
        "expected_database_secret_file": paths["database"],
        "expected_head_anchor_authority_file": paths["authority"],
        "expected_head_anchor_auth_secret_file": paths["auth"],
        "expected_head_anchor_signing_key_secret_file": paths["signing"],
        "database_secret_consumed_before": _marker_candidate(),
        "database_secret_consumed_after": _marker_candidate(),
        "release_path_absences_before": _absence_candidates(release_paths),
        "release_path_absences_after": _absence_candidates(list(reversed(release_paths))),
        "staged_input_retirements_before": _absence_candidates(staged_path_strings),
        "staged_input_retirements_after": _absence_candidates(list(reversed(staged_path_strings))),
    }


def _validate(
    inputs: dict[str, object],
) -> TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
    return validate_post_enrollment_start_staged_unreleased_topology(**inputs)  # type: ignore[arg-type]


def _mutate(
    inspection: object,
    path: tuple[str | int, ...],
    value: object,
) -> object:
    mutated = deepcopy(inspection)
    cursor = mutated
    for part in path[:-1]:
        cursor = cast(dict[object, object] | list[object], cursor)[part]  # type: ignore[index]
    cast(dict[object, object] | list[object], cursor)[path[-1]] = value  # type: ignore[index]
    return mutated


def test_staged_unreleased_topology_binds_exact_running_state(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)

    snapshot = _validate(inputs)

    assert snapshot.status == POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS
    assert snapshot.payload()["contract_version"] == (
        POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION
    )
    assert snapshot.source.container_id == SOURCE_CONTAINER_ID
    assert snapshot.supervisor.container_id == SUPERVISOR_CONTAINER_ID
    assert (
        snapshot.created_topology_snapshot_sha256
        == cast(
            TrustedTimePostEnrollmentCreatedTopologySnapshot,
            inputs["created_topology"],
        ).snapshot_sha256
    )
    assert len(snapshot.stable_topology_sha256) == 64
    assert len(snapshot.snapshot_sha256) == 64


def test_staged_payload_is_digest_only_and_every_authority_is_false(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    snapshot = _validate(inputs)
    payload = snapshot.payload()

    false_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | {
        "authority_granted",
        "claim_retention_authorized",
        "container_identity_authenticated",
        "created_topology_authenticated",
        "daemon_identity_authenticated",
        "database_secret_consumption_authenticated",
        "database_secret_disclosed",
        "inventory_authenticated",
        "observation_provenance_authenticated",
        "persistent_start_authorized",
        "release_absence_authenticated",
        "release_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "source_start_authenticated",
        "source_start_authorized",
        "staged_input_retirement_authenticated",
        "start_order_authenticated",
        "supervisor_start_authenticated",
        "supervisor_start_authorized",
        "topology_authenticated",
        "topology_mutation_authorized",
        "volume_identity_authenticated",
    }
    assert false_fields.issubset(payload)
    assert all(payload[field] is False for field in false_fields)
    assert all(getattr(snapshot, field) is False for field in false_fields)

    encoded = json.dumps(payload, sort_keys=True)
    for key in (
        "container_inspections",
        "environment",
        "health",
        "health_log",
        "mounts",
        "release_path_absences",
        "start_argv",
        "staged_path",
    ):
        assert key not in encoded.lower()
    for path in _staged_paths(tmp_path).values():
        assert str(path) not in encoded
    assert POST_ENROLLMENT_START_RELEASE_PATH not in encoded
    assert POST_ENROLLMENT_START_RELEASE_STAGING_PATH not in encoded


def test_staged_snapshot_is_frozen(tmp_path: Path) -> None:
    snapshot = _validate(_valid_inputs(tmp_path))

    with pytest.raises(FrozenInstanceError):
        snapshot.daemon_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        snapshot.source.container_id = OTHER_CONTAINER_ID  # type: ignore[misc]


def test_staged_snapshot_ignores_volatile_source_health_log(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    first = _validate(inputs)
    inspections = cast(dict[str, object], inputs["container_inspections"])
    source = cast(list[dict[str, object]], inspections[SOURCE_CONTAINER_ID])
    health = cast(dict[str, object], cast(dict[str, object], source[0]["State"])["Health"])
    health["Log"] = [
        {
            "End": "2026-08-09T12:36:01.000000000Z",
            "ExitCode": 0,
            "Output": "later healthy output\n",
            "Start": "2026-08-09T12:36:00.000000000Z",
        }
    ]

    second = _validate(inputs)

    assert second.source.stable_inspection_projection_sha256 == (
        first.source.stable_inspection_projection_sha256
    )
    assert second.source.running_state_projection_sha256 == (
        first.source.running_state_projection_sha256
    )
    assert second.stable_topology_sha256 == first.stable_topology_sha256
    assert second.snapshot_sha256 == first.snapshot_sha256


def test_staged_snapshot_is_order_independent(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    expected = _validate(inputs)
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inputs["container_inspections"] = dict(reversed(tuple(inspections.items())))
    inputs["project_container_ids_before"] = (
        SUPERVISOR_CONTAINER_ID,
        SOURCE_CONTAINER_ID,
    )
    inputs["project_container_ids_after"] = (
        SOURCE_CONTAINER_ID,
        SUPERVISOR_CONTAINER_ID,
    )

    observed = _validate(inputs)

    assert observed.payload() == expected.payload()
    assert observed.snapshot_sha256 == expected.snapshot_sha256


@pytest.mark.parametrize(
    "drift",
    [
        "approval_operation",
        "approved_git_revision",
        "approved_admission",
        "approved_source_image",
        "approved_supervisor_image",
        "created_operation",
        "created_approval",
        "created_review",
        "created_enrollment",
        "created_launch",
        "created_daemon_context",
        "created_daemon_endpoint",
        "created_daemon_id",
        "created_socket_volume",
        "created_state_volume",
    ],
)
def test_staged_topology_rejects_approval_launch_or_created_binding_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    approval = cast(TrustedTimePostEnrollmentStartApproval, inputs["approval"])
    approved = cast(TrustedTimeApprovedLaunch, inputs["approved_launch"])
    created = cast(
        TrustedTimePostEnrollmentCreatedTopologySnapshot,
        inputs["created_topology"],
    )
    if drift == "approval_operation":
        inputs["approval"] = replace(
            approval,
            operation_id="323e4567-e89b-42d3-a456-426614174002",
        )
    elif drift.startswith("approved_"):
        field_name, value = {
            "approved_git_revision": ("git_revision", "e" * 40),
            "approved_admission": ("image_admission_sha256", "e" * 64),
            "approved_source_image": ("source_image_id", "sha256:" + "e" * 64),
            "approved_supervisor_image": (
                "supervisor_image_id",
                "sha256:" + "e" * 64,
            ),
        }[drift]
        inputs["approved_launch"] = replace(approved, **{field_name: value})
    elif drift == "created_launch":
        inputs["created_topology"] = replace(
            created,
            approved_launch=replace(created.approved_launch, git_revision="e" * 40),
        )
    else:
        field_name, value = {
            "created_operation": (
                "operation_id",
                "323e4567-e89b-42d3-a456-426614174002",
            ),
            "created_approval": ("approval_sha256", "e" * 64),
            "created_review": ("review_projection_sha256", "e" * 64),
            "created_enrollment": (
                "confirmed_enrollment_evidence_sha256",
                "e" * 64,
            ),
            "created_daemon_context": ("daemon_context_name", "other-context"),
            "created_daemon_endpoint": (
                "daemon_endpoint",
                "unix:///other/docker.sock",
            ),
            "created_daemon_id": ("daemon_id", "OTHER:DAEMON:2"),
            "created_socket_volume": ("socket_volume_sha256", "e" * 64),
            "created_state_volume": ("state_volume_sha256", "e" * 64),
        }[drift]
        inputs["created_topology"] = replace(
            created,
            **{field_name: value},  # type: ignore[arg-type]
        )

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "drift",
    [
        "daemon_before_context",
        "daemon_before_endpoint",
        "daemon_before_id",
        "daemon_after_context",
        "daemon_after_endpoint",
        "daemon_after_id",
        "volume_before_socket",
        "volume_before_state",
        "volume_after_socket",
        "volume_after_state",
    ],
)
def test_staged_topology_rejects_daemon_or_volume_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    if drift.startswith("daemon_"):
        daemon = _daemon_identity()
        changed = LocalDockerDaemonIdentity(
            context_name=("other-context" if drift.endswith("context") else daemon.context_name),
            endpoint=(
                "unix:///other/docker.sock" if drift.endswith("endpoint") else daemon.endpoint
            ),
            daemon_id=("OTHER:DAEMON:2" if drift.endswith("id") else daemon.daemon_id),
        )
        inputs["daemon_identity_before" if "_before_" in drift else "daemon_identity_after"] = (
            changed
        )
    else:
        volumes = _volume_identities()
        changed_volumes = TrustedTimeVolumeIdentities(
            socket_sha256=("c" * 64 if drift.endswith("socket") else volumes.socket_sha256),
            state_sha256=("d" * 64 if drift.endswith("state") else volumes.state_sha256),
        )
        inputs["volume_identities_before" if "_before_" in drift else "volume_identities_after"] = (
            changed_volumes
        )

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ((SOURCE_CONTAINER_ID,), (SOURCE_CONTAINER_ID,)),
        (
            (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID, OTHER_CONTAINER_ID),
            (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID, OTHER_CONTAINER_ID),
        ),
        (
            (SOURCE_CONTAINER_ID, SOURCE_CONTAINER_ID),
            (SOURCE_CONTAINER_ID, SOURCE_CONTAINER_ID),
        ),
        (
            (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID),
            (SOURCE_CONTAINER_ID, OTHER_CONTAINER_ID),
        ),
        (("a" * 63, SUPERVISOR_CONTAINER_ID), ("a" * 63, SUPERVISOR_CONTAINER_ID)),
        (
            [SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID],
            [SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID],
        ),
    ],
)
def test_staged_topology_rejects_invalid_or_changed_inventory(
    tmp_path: Path,
    before: object,
    after: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs["project_container_ids_before"] = before
    inputs["project_container_ids_after"] = after

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "key_id_mismatch",
        "key_subclass",
        "project",
        "unknown_role",
        "duplicate_role",
    ],
)
def test_staged_topology_requires_exact_id_keyed_role_derived_inspections(
    tmp_path: Path,
    mutation: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, object], inputs["container_inspections"])
    if mutation == "missing":
        inspections.pop(SUPERVISOR_CONTAINER_ID)
    elif mutation == "extra":
        inspections[OTHER_CONTAINER_ID] = deepcopy(inspections[SOURCE_CONTAINER_ID])
    elif mutation == "key_id_mismatch":
        source = cast(list[dict[str, object]], inspections[SOURCE_CONTAINER_ID])
        inspections[SOURCE_CONTAINER_ID] = _mutate(source, (0, "Id"), OTHER_CONTAINER_ID)
    elif mutation == "key_subclass":
        raw_source = inspections.pop(SOURCE_CONTAINER_ID)
        inspections[_EqualString(SOURCE_CONTAINER_ID)] = raw_source
    else:
        source = cast(list[dict[str, object]], inspections[SOURCE_CONTAINER_ID])
        label, value = {
            "project": ("com.docker.compose.project", "other-project"),
            "unknown_role": ("com.docker.compose.service", "unknown-service"),
            "duplicate_role": (
                "com.docker.compose.service",
                "trusted-time-supervisor",
            ),
        }[mutation]
        inspections[SOURCE_CONTAINER_ID] = _mutate(
            source,
            (0, "Config", "Labels", label),
            value,
        )

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("source", (0, "Image"), SUPERVISOR_IMAGE_ID),
        ("source", (0, "Config", "Image"), SUPERVISOR_IMAGE_ID),
        ("source", (0, "Path"), "/bin/sh"),
        ("source", (0, "Config", "User"), "0:0"),
        ("supervisor", (0, "Image"), SOURCE_IMAGE_ID),
        ("supervisor", (0, "Config", "Image"), SOURCE_IMAGE_ID),
        ("supervisor", (0, "Args"), ["--unexpected"]),
        ("supervisor", (0, "Config", "User"), "0:0"),
    ],
)
def test_staged_topology_rejects_container_identity_image_or_config_drift(
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inspections[container_id] = _mutate(inspections[container_id], path, value)

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("role", ["source", "supervisor"])
def test_staged_topology_rejects_submitted_image_configuration_drift(
    tmp_path: Path,
    role: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    configuration = cast(dict[str, object], inputs[f"{role}_image_configuration"])
    configuration["User"] = "0:0"

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("supervisor", (0, "State", "Status"), "exited"),
        ("supervisor", (0, "State", "Running"), False),
        ("supervisor", (0, "State", "Paused"), True),
        ("supervisor", (0, "State", "Pid"), 0),
        ("supervisor", (0, "State", "Pid"), True),
        ("supervisor", (0, "State", "StartedAt"), ZERO_DOCKER_TIMESTAMP),
        ("supervisor", (0, "State", "FinishedAt"), STARTED_AT),
        ("supervisor", (0, "RestartCount"), 1),
        ("source", (0, "State", "Health", "Status"), "unhealthy"),
        ("source", (0, "State", "Health", "FailingStreak"), 1),
        ("source", (0, "State", "Health", "Log"), ()),
    ],
)
def test_staged_topology_rejects_nonexact_running_or_health_state(
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inspections[container_id] = _mutate(inspections[container_id], path, value)

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("path", "/tmp/not-the-consumed-marker"),
        ("path", _EqualString(DATABASE_SECRET_CONSUMED_PATH)),
        ("byte_sha256", "A" * 64),
        ("byte_sha256", _EqualString(DATABASE_SECRET_CONSUMED_SHA256)),
        ("size", 0),
        ("size", True),
        ("owner_uid", 0),
        ("owner_uid", True),
        ("owner_gid", 0),
        ("mode", 0o600),
        ("link_count", 2),
        ("regular", False),
        ("regular", 1),
        ("device", -1),
        ("device", True),
        ("inode", 0),
        ("inode", True),
        ("modified_time_ns", -1),
        ("modified_time_ns", True),
        ("changed_time_ns", -1),
        ("changed_time_ns", True),
        ("device", 1 << 256),
        ("inode", 1 << 256),
        ("modified_time_ns", 1 << 256),
        ("changed_time_ns", 1 << 256),
    ],
)
def test_consumed_marker_candidate_rejects_wrong_types_metadata_and_huge_integers(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _marker_candidate(**{field_name: value})


def test_staged_topology_rejects_consumed_marker_two_pass_race(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs["database_secret_consumed_after"] = _marker_candidate(inode=6)

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("relative/path", "absent"),
        ("/tmp/../tmp/path", "absent"),
        ("//tmp/path", "absent"),
        ("/tmp/path\nname", "absent"),
        (_EqualString("/tmp/path"), "absent"),
        ("/tmp/path", _EqualString("absent")),
        ("/tmp/path", "present"),
        ("/tmp/path", 0),
    ],
)
def test_absent_path_candidate_requires_canonical_exact_absence(
    path: str,
    status: object,
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        TrustedTimePostEnrollmentAbsentPathCandidate(path=path, status=status)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("family", "mutation"),
    [
        ("release", "missing"),
        ("release", "duplicate"),
        ("release", "wrong"),
        ("release", "present_after"),
        ("release", "path_subclass_after"),
        ("release", "status_subclass_after"),
        ("retirement", "missing"),
        ("retirement", "duplicate"),
        ("retirement", "wrong"),
        ("retirement", "present_after"),
    ],
)
def test_staged_topology_rejects_inexact_or_racing_absence_candidates(
    tmp_path: Path,
    family: str,
    mutation: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    prefix = "release_path_absences" if family == "release" else "staged_input_retirements"
    before_key = f"{prefix}_before"
    after_key = f"{prefix}_after"
    before = list(
        cast(tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...], inputs[before_key])
    )
    after = list(cast(tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...], inputs[after_key]))
    if mutation == "missing":
        before.pop()
        after.pop()
    elif mutation == "duplicate":
        before[-1] = before[0]
        after[-1] = after[0]
    elif mutation == "wrong":
        wrong = TrustedTimePostEnrollmentAbsentPathCandidate(path="/tmp/unexpected-path")
        before[-1] = wrong
        after[-1] = wrong
    elif mutation == "present_after":
        object.__setattr__(after[0], "status", "present")
    elif mutation == "path_subclass_after":

        class EqualPath(str):
            pass

        object.__setattr__(after[0], "path", EqualPath(after[0].path))
    else:

        class EqualStatus(str):
            pass

        object.__setattr__(after[0], "status", EqualStatus("absent"))
    inputs[before_key] = tuple(before)
    inputs[after_key] = tuple(after)

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "field_name",
    [
        "expected_database_secret_file",
        "expected_head_anchor_authority_file",
        "expected_head_anchor_auth_secret_file",
        "expected_head_anchor_signing_key_secret_file",
    ],
)
@pytest.mark.parametrize("invalid", [None, "not-a-path", Path("relative/input")])
def test_staged_topology_requires_exact_absolute_staged_paths(
    tmp_path: Path,
    field_name: str,
    invalid: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs[field_name] = invalid

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


def test_staged_topology_requires_four_distinct_staged_paths(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs["expected_head_anchor_auth_secret_file"] = inputs["expected_database_secret_file"]

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


def test_staged_topology_rejects_equal_daemon_after_string_subclass(
    tmp_path: Path,
) -> None:
    inputs = _valid_inputs(tmp_path)
    daemon_after = _daemon_identity()

    class EqualDaemonId(str):
        pass

    object.__setattr__(daemon_after, "daemon_id", EqualDaemonId(daemon_after.daemon_id))
    inputs["daemon_identity_after"] = daemon_after

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "field_name",
    [
        "approval",
        "approved_launch",
        "created_topology",
        "daemon_identity_before",
        "daemon_identity_after",
        "volume_identities_before",
        "volume_identities_after",
        "container_inspections",
        "source_image_configuration",
        "supervisor_image_configuration",
        "database_secret_consumed_before",
        "database_secret_consumed_after",
    ],
)
def test_staged_topology_rejects_wrong_exact_input_types(
    tmp_path: Path,
    field_name: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs[field_name] = object()

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "field_name",
    [
        "project_container_ids_before",
        "project_container_ids_after",
        "release_path_absences_before",
        "release_path_absences_after",
        "staged_input_retirements_before",
        "staged_input_retirements_after",
    ],
)
def test_staged_topology_rejects_list_for_exact_tuple_inputs(
    tmp_path: Path,
    field_name: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs[field_name] = list(cast(tuple[object, ...], inputs[field_name]))

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("unsupported", [b"not-json", float("nan"), {1, 2}, ("tuple",)])
def test_staged_topology_rejects_unsupported_non_json_projections(
    tmp_path: Path,
    unsupported: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    configuration = cast(dict[str, object], inputs["source_image_configuration"])
    configuration["Unsupported"] = unsupported

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("shape", [None, {}, [], [[], {}], [{}, {}], ["not-a-container"]])
def test_staged_topology_rejects_malformed_inspection_shapes(
    tmp_path: Path,
    shape: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inspections[SOURCE_CONTAINER_ID] = shape

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(inputs)


def test_staged_topology_rejects_cyclic_oversize_and_huge_integer_projections(
    tmp_path: Path,
) -> None:
    cyclic = _valid_inputs(tmp_path)
    cyclic_configuration = cast(dict[str, object], cyclic["source_image_configuration"])
    cyclic_configuration["cycle"] = cyclic_configuration
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(cyclic)

    oversize = _valid_inputs(tmp_path)
    oversize_configuration = cast(dict[str, object], oversize["source_image_configuration"])
    oversize_configuration["oversize"] = "x" * (4 * 1_024 * 1_024 + 1)
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(oversize)

    huge_integer = _valid_inputs(tmp_path)
    huge_configuration = cast(dict[str, object], huge_integer["source_image_configuration"])
    huge_configuration["integer"] = 1 << 256
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        _validate(huge_integer)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("operation_id", "not-a-uuid"),
        ("operation_id", "223E4567-E89B-42D3-A456-426614174001"),
        ("approval_sha256", "not-a-digest"),
        ("created_topology_snapshot_sha256", "A" * 64),
        ("daemon_endpoint", "unix:///tmp/../docker.sock"),
        ("database_secret_consumed_candidate_sha256", "0" * 63),
        ("release_paths_absence_candidate_sha256", object()),
        ("approved_launch", object()),
        ("source", object()),
    ],
)
def test_staged_snapshot_constructor_rejects_invalid_manual_fields(
    tmp_path: Path,
    field_name: str,
    value: object,
) -> None:
    snapshot = _validate(_valid_inputs(tmp_path))

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        replace(snapshot, **{field_name: value})  # type: ignore[arg-type]


def test_staged_snapshot_constructor_rejects_duplicate_ids_and_nested_drift(
    tmp_path: Path,
) -> None:
    snapshot = _validate(_valid_inputs(tmp_path))
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        replace(
            snapshot,
            supervisor=replace(snapshot.supervisor, container_id=snapshot.source.container_id),
        )
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        replace(
            snapshot,
            source=replace(snapshot.source, image_id="sha256:" + "e" * 64),
        )
    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        replace(snapshot.source, running_state_projection_sha256="A" * 64)


def test_staged_snapshot_constructor_rejects_duck_typed_nested_impostor(
    tmp_path: Path,
) -> None:
    snapshot = _validate(_valid_inputs(tmp_path))

    class MutableContainerImpostor:
        service = "chrony-nts"
        container_id = SOURCE_CONTAINER_ID
        image_id = SOURCE_IMAGE_ID

        def __post_init__(self) -> None:
            return None

        def payload(self) -> dict[str, str]:
            return {"raw_secret": "must-not-survive"}

    with pytest.raises(TrustedTimePostEnrollmentStagedTopologyRejected):
        replace(snapshot, source=MutableContainerImpostor())  # type: ignore[arg-type]


@pytest.mark.parametrize("drift", ["pid", "started_at", "config", "marker_identity"])
def test_stable_snapshot_digest_changes_for_nonvolatile_observation_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    baseline = _validate(_valid_inputs(tmp_path))
    inputs = _valid_inputs(tmp_path)
    if drift == "marker_identity":
        inputs["database_secret_consumed_before"] = _marker_candidate(inode=99)
        inputs["database_secret_consumed_after"] = _marker_candidate(inode=99)
    else:
        inspections = cast(dict[str, object], inputs["container_inspections"])
        if drift == "pid":
            inspections[SUPERVISOR_CONTAINER_ID] = _mutate(
                inspections[SUPERVISOR_CONTAINER_ID],
                (0, "State", "Pid"),
                202,
            )
        elif drift == "started_at":
            inspections[SUPERVISOR_CONTAINER_ID] = _mutate(
                inspections[SUPERVISOR_CONTAINER_ID],
                (0, "State", "StartedAt"),
                "2026-08-09T12:35:56.000000000Z",
            )
        else:
            inspections[SUPERVISOR_CONTAINER_ID] = _mutate(
                inspections[SUPERVISOR_CONTAINER_ID],
                (0, "Config", "RuntimeObservation"),
                "changed",
            )

    changed = _validate(inputs)

    assert changed.stable_topology_sha256 != baseline.stable_topology_sha256
    assert changed.snapshot_sha256 != baseline.snapshot_sha256


def test_staged_snapshot_isolated_copy_and_digest_remain_stable(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    snapshot = _validate(inputs)
    original_payload = snapshot.payload()
    original_digest = snapshot.snapshot_sha256

    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[SOURCE_CONTAINER_ID][0]["Image"] = "sha256:" + "e" * 64
    cast(dict[str, object], inputs["source_image_configuration"])["User"] = "0:0"
    marker = cast(
        TrustedTimePostEnrollmentConsumedMarkerCandidate,
        inputs["database_secret_consumed_before"],
    )
    object.__setattr__(marker, "inode", 999)

    assert snapshot.payload() == original_payload
    assert snapshot.snapshot_sha256 == original_digest


def test_staged_validation_performs_no_io_execution_claim_or_release(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    with (
        patch("builtins.open", side_effect=AssertionError("file must not be opened")) as opened,
        patch(
            "pathlib.Path.read_bytes",
            side_effect=AssertionError("file must not be read"),
        ) as read_bytes,
        patch(
            "pathlib.Path.read_text",
            side_effect=AssertionError("file must not be read"),
        ) as read_text,
        patch("os.open", side_effect=AssertionError("file must not be opened")) as os_open,
        patch("os.stat", side_effect=AssertionError("file must not be stated")) as os_stat,
        patch("time.time", side_effect=AssertionError("clock must not be read")) as wall_clock,
        patch(
            "time.monotonic",
            side_effect=AssertionError("clock must not be read"),
        ) as monotonic_clock,
        patch(
            "subprocess.run",
            side_effect=AssertionError("subprocess must not run"),
        ) as raw_subprocess_run,
        patch(
            "subprocess.Popen",
            side_effect=AssertionError("subprocess must not run"),
        ) as raw_subprocess_popen,
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=AssertionError("Docker must not run"),
        ) as docker,
        patch(
            "scripts.start_trusted_time_supervisor.run_bounded_subprocess",
            side_effect=AssertionError("subprocess must not run"),
        ) as subprocess_runner,
        patch.object(
            post_enrollment_start_script,
            "retain_post_enrollment_start_claim",
            side_effect=AssertionError("claim must not be retained"),
        ) as retain_claim,
        patch(
            "apps.trusted_time_supervisor.post_enrollment_release.write_post_enrollment_start_release",
            side_effect=AssertionError("release must not be published"),
        ) as release,
    ):
        snapshot = _validate(inputs)

    assert snapshot.status == POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS
    opened.assert_not_called()
    read_bytes.assert_not_called()
    read_text.assert_not_called()
    os_open.assert_not_called()
    os_stat.assert_not_called()
    wall_clock.assert_not_called()
    monotonic_clock.assert_not_called()
    raw_subprocess_run.assert_not_called()
    raw_subprocess_popen.assert_not_called()
    docker.assert_not_called()
    subprocess_runner.assert_not_called()
    retain_claim.assert_not_called()
    release.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_staged_snapshot_has_frozen_golden_digest() -> None:
    snapshot = _validate(_valid_inputs(Path("/private/autoquant-golden/runtime-secrets")))

    assert (
        snapshot.stable_topology_sha256
        == hashlib.sha256(
            canonical_first_enrollment_json_bytes(snapshot.stable_topology_payload())
        ).hexdigest()
    )
    assert snapshot.stable_topology_sha256 == (
        "06131fba5c6ea0c0a49837dd585de0bd6f244b100add10cbd0a0c22ba504ebcf"
    )
    assert snapshot.snapshot_sha256 == (
        "4e365aadfa588ec40897cd0ed007cebf46bc4f03b02e8051dbe6dfea8d22df89"
    )
