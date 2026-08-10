from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Literal, cast
from unittest.mock import patch

import pytest

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
    DATABASE_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
)
from scripts.trusted_time_post_enrollment_topology import (
    _MAXIMUM_JSON_PROJECTION_BYTES,
    _MAXIMUM_JSON_PROJECTION_NODES,
    POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
    POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS,
    TrustedTimePostEnrollmentCreatedTopologyRejected,
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    _require_exact_json_tree,
    validate_post_enrollment_start_created_topology,
)

SOURCE_CONTAINER_ID = "a" * 64
SUPERVISOR_CONTAINER_ID = "b" * 64
OTHER_CONTAINER_ID = "c" * 64
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
PROJECT_NAME = "autoquanttrader-trusted-time"
ZERO_DOCKER_TIMESTAMP = "0001-01-01T00:00:00Z"
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
    (f"AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE={HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH}"),
]

_TOP_LEVEL_INSPECTION_KEYS = {
    "Args",
    "Config",
    "HostConfig",
    "Id",
    "Image",
    "Mounts",
    "NetworkSettings",
    "Path",
    "RestartCount",
    "State",
}
_CONFIGURATION_KEYS = {
    "Cmd",
    "Entrypoint",
    "Env",
    "ExposedPorts",
    "Healthcheck",
    "Image",
    "Labels",
    "NetworkDisabled",
    "StopSignal",
    "User",
    "WorkingDir",
}
_HOST_CONFIGURATION_KEYS = {
    "AutoRemove",
    "Binds",
    "CapAdd",
    "CapDrop",
    "Cgroup",
    "CgroupnsMode",
    "DeviceCgroupRules",
    "DeviceRequests",
    "Devices",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "ExtraHosts",
    "GroupAdd",
    "Init",
    "IpcMode",
    "Links",
    "LogConfig",
    "MaskedPaths",
    "Memory",
    "Mounts",
    "NanoCpus",
    "NetworkMode",
    "OomKillDisable",
    "PidMode",
    "PidsLimit",
    "PortBindings",
    "Privileged",
    "PublishAllPorts",
    "ReadonlyPaths",
    "ReadonlyRootfs",
    "RestartPolicy",
    "SecurityOpt",
    "Sysctls",
    "Tmpfs",
    "UTSMode",
    "UsernsMode",
    "VolumesFrom",
}
_STATE_KEYS = {
    "Dead",
    "Error",
    "ExitCode",
    "FinishedAt",
    "OOMKilled",
    "Paused",
    "Pid",
    "Restarting",
    "Running",
    "StartedAt",
    "Status",
}


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


def _approved_launch() -> TrustedTimeApprovedLaunch:
    proposed = _approval().proposed_launch
    return TrustedTimeApprovedLaunch(
        git_revision=proposed.git_revision,
        image_admission_sha256=proposed.image_admission_sha256,
        source_image_id=proposed.source_image_id,
        supervisor_image_id=proposed.supervisor_image_id,
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


def _created_state() -> dict[str, object]:
    return {
        "Dead": False,
        "Error": "",
        "ExitCode": 0,
        "FinishedAt": ZERO_DOCKER_TIMESTAMP,
        "OOMKilled": False,
        "Paused": False,
        "Pid": 0,
        "Restarting": False,
        "Running": False,
        "StartedAt": ZERO_DOCKER_TIMESTAMP,
        "Status": "created",
    }


def _labels(role: Literal["source", "supervisor"]) -> dict[str, str]:
    return {
        "com.docker.compose.container-number": "1",
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.project": PROJECT_NAME,
        "com.docker.compose.service": (
            "chrony-nts" if role == "source" else "trusted-time-supervisor"
        ),
    }


def _volume_request(
    *,
    source: str,
    target: str,
    nocopy: bool,
) -> dict[str, object]:
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


def _created_container_inspection(
    *,
    role: Literal["source", "supervisor"],
    container_id: str,
    image_id: str,
    staged_paths: dict[str, Path],
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
            "State": _created_state(),
        }
    ]


def _mutated_inspection(
    inspection: list[dict[str, object]],
    path: tuple[str | int, ...],
    value: object,
) -> list[dict[str, object]]:
    mutated = deepcopy(inspection)
    cursor: object = mutated
    for field in path[:-1]:
        cursor = cast(dict[object, object] | list[object], cursor)[field]  # type: ignore[index]
    cast(dict[object, object] | list[object], cursor)[path[-1]] = value  # type: ignore[index]
    return mutated


def _valid_inputs(
    root: Path,
    *,
    reverse_inventory_before: bool = False,
    reverse_inventory_after: bool = False,
    reverse_inspections: bool = False,
) -> dict[str, object]:
    paths = _staged_paths(root)
    source = _created_container_inspection(
        role="source",
        container_id=SOURCE_CONTAINER_ID,
        image_id=SOURCE_IMAGE_ID,
        staged_paths=paths,
    )
    supervisor = _created_container_inspection(
        role="supervisor",
        container_id=SUPERVISOR_CONTAINER_ID,
        image_id=SUPERVISOR_IMAGE_ID,
        staged_paths=paths,
    )
    ordered_inspections = (
        (
            (SUPERVISOR_CONTAINER_ID, supervisor),
            (SOURCE_CONTAINER_ID, source),
        )
        if reverse_inspections
        else (
            (SOURCE_CONTAINER_ID, source),
            (SUPERVISOR_CONTAINER_ID, supervisor),
        )
    )
    inventory = (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID)
    return {
        "approval": _approval(),
        "approved_launch": _approved_launch(),
        "daemon_identity_before": _daemon_identity(),
        "daemon_identity_after": _daemon_identity(),
        "volume_identities_before": _volume_identities(),
        "volume_identities_after": _volume_identities(),
        "project_container_ids_before": (
            tuple(reversed(inventory)) if reverse_inventory_before else inventory
        ),
        "project_container_ids_after": (
            tuple(reversed(inventory)) if reverse_inventory_after else inventory
        ),
        "container_inspections": dict(ordered_inspections),
        "source_image_configuration": _image_configuration("source"),
        "supervisor_image_configuration": _image_configuration("supervisor"),
        "expected_database_secret_file": paths["database"],
        "expected_head_anchor_authority_file": paths["authority"],
        "expected_head_anchor_auth_secret_file": paths["auth"],
        "expected_head_anchor_signing_key_secret_file": paths["signing"],
    }


def _validate(inputs: dict[str, object]) -> TrustedTimePostEnrollmentCreatedTopologySnapshot:
    return validate_post_enrollment_start_created_topology(**inputs)  # type: ignore[arg-type]


def test_created_container_fixtures_have_exact_narrow_payload_shape(tmp_path: Path) -> None:
    paths = _staged_paths(tmp_path)
    for role, container_id, image_id in (
        ("source", SOURCE_CONTAINER_ID, SOURCE_IMAGE_ID),
        ("supervisor", SUPERVISOR_CONTAINER_ID, SUPERVISOR_IMAGE_ID),
    ):
        inspection = _created_container_inspection(
            role=cast(Literal["source", "supervisor"], role),
            container_id=container_id,
            image_id=image_id,
            staged_paths=paths,
        )
        assert len(inspection) == 1
        assert set(inspection[0]) == _TOP_LEVEL_INSPECTION_KEYS
        assert set(cast(dict[str, object], inspection[0]["Config"])) == _CONFIGURATION_KEYS
        assert set(cast(dict[str, object], inspection[0]["HostConfig"])) == (
            _HOST_CONFIGURATION_KEYS
        )
        assert set(cast(dict[str, object], inspection[0]["State"])) == _STATE_KEYS


@pytest.mark.parametrize(
    ("reverse_before", "reverse_after", "reverse_inspections"),
    [
        (False, False, False),
        (True, False, False),
        (False, True, True),
        (True, True, True),
    ],
)
def test_created_topology_snapshot_derives_roles_and_fixed_start_order(
    tmp_path: Path,
    reverse_before: bool,
    reverse_after: bool,
    reverse_inspections: bool,
) -> None:
    snapshot = _validate(
        _valid_inputs(
            tmp_path,
            reverse_inventory_before=reverse_before,
            reverse_inventory_after=reverse_after,
            reverse_inspections=reverse_inspections,
        )
    )

    assert type(snapshot) is TrustedTimePostEnrollmentCreatedTopologySnapshot
    assert snapshot.source.container_id == SOURCE_CONTAINER_ID
    assert snapshot.source.service == "chrony-nts"
    assert snapshot.supervisor.container_id == SUPERVISOR_CONTAINER_ID
    assert snapshot.supervisor.service == "trusted-time-supervisor"
    assert snapshot.source_start_argv == (
        "docker",
        "container",
        "start",
        SOURCE_CONTAINER_ID,
    )
    assert snapshot.supervisor_start_argv == (
        "docker",
        "container",
        "start",
        SUPERVISOR_CONTAINER_ID,
    )


def test_created_topology_payload_is_exact_frozen_and_non_authorizing(tmp_path: Path) -> None:
    snapshot = _validate(_valid_inputs(tmp_path))
    payload = snapshot.payload()
    expected_fields = {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        "approval_sha256",
        "approved_launch",
        "authority_granted",
        "claim_retention_authorized",
        "compose_project",
        "confirmed_enrollment_evidence_sha256",
        "container_identity_authenticated",
        "contract_version",
        "daemon_identity",
        "daemon_identity_authenticated",
        "database_secret_disclosed",
        "inventory_authenticated",
        "operation_id",
        "persistent_start_authorized",
        "release_authorized",
        "review_projection_sha256",
        "sequence_2_authorized",
        "service",
        "shutdown_authorized",
        "source_container",
        "source_start_authorized",
        "start_order_argv",
        "status",
        "submitted_project_container_count",
        "supervisor_container",
        "supervisor_start_authorized",
        "topology_authenticated",
        "topology_mutation_authorized",
        "volume_identities",
        "volume_identity_authenticated",
    }
    container_fields = {
        "container_id",
        "image_configuration_projection_sha256",
        "image_id",
        "inspection_projection_sha256",
        "service",
    }

    assert set(payload) == expected_fields
    assert set(cast(dict[str, object], payload["source_container"])) == container_fields
    assert set(cast(dict[str, object], payload["supervisor_container"])) == container_fields
    assert payload["contract_version"] == POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION
    assert payload["status"] == POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS
    assert snapshot.status == POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS
    assert payload["start_order_argv"] == [
        ["docker", "container", "start", SOURCE_CONTAINER_ID],
        ["docker", "container", "start", SUPERVISOR_CONTAINER_ID],
    ]
    false_fields = FIRST_ENROLLMENT_AUTHORITY_FIELDS | {
        "authority_granted",
        "claim_retention_authorized",
        "container_identity_authenticated",
        "daemon_identity_authenticated",
        "database_secret_disclosed",
        "inventory_authenticated",
        "persistent_start_authorized",
        "release_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "source_start_authorized",
        "supervisor_start_authorized",
        "topology_authenticated",
        "topology_mutation_authorized",
        "volume_identity_authenticated",
    }
    assert all(payload[field_name] is False for field_name in false_fields)
    assert all(getattr(snapshot, field_name) is False for field_name in false_fields)
    assert snapshot.observation_provenance_authenticated is False
    assert snapshot.source_start_authenticated is False
    assert snapshot.start_order_authenticated is False
    assert snapshot.supervisor_start_authenticated is False
    assert "observation_provenance_authenticated" not in payload
    assert "source_start_authenticated" not in payload
    assert "start_order_authenticated" not in payload
    assert "supervisor_start_authenticated" not in payload
    assert len(snapshot.snapshot_sha256) == 64
    with pytest.raises(FrozenInstanceError):
        snapshot.daemon_id = "changed"  # type: ignore[misc]
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        replace(snapshot, source_start_argv=("docker", "container", "start", OTHER_CONTAINER_ID))


def test_created_topology_snapshot_has_frozen_golden_digest() -> None:
    snapshot = _validate(_valid_inputs(Path("/private/autoquant-golden/runtime-secrets")))

    assert snapshot.snapshot_sha256 == (
        "140b48178091967c3fd99e8db8883e9c32eb7ddcd4bfd19003f619dcaca69ec1"
    )


@pytest.mark.parametrize(
    "drift",
    [
        "approved_git_revision",
        "approved_admission",
        "approved_source_image",
        "approved_supervisor_image",
        "daemon_context",
        "daemon_endpoint",
        "daemon_id",
        "socket_volume",
        "state_volume",
    ],
)
def test_created_topology_rejects_approval_daemon_or_volume_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    if drift.startswith("approved_"):
        approved = cast(TrustedTimeApprovedLaunch, inputs["approved_launch"])
        changes: dict[str, str] = {
            "approved_git_revision": "e" * 40,
            "approved_admission": "e" * 64,
            "approved_source_image": "sha256:" + "e" * 64,
            "approved_supervisor_image": "sha256:" + "e" * 64,
        }
        field_names = {
            "approved_git_revision": "git_revision",
            "approved_admission": "image_admission_sha256",
            "approved_source_image": "source_image_id",
            "approved_supervisor_image": "supervisor_image_id",
        }
        inputs["approved_launch"] = replace(
            approved,
            **{field_names[drift]: changes[drift]},
        )
    elif drift.startswith("daemon_"):
        daemon = _daemon_identity()
        inputs["daemon_identity_after"] = LocalDockerDaemonIdentity(
            context_name=("other-context" if drift == "daemon_context" else daemon.context_name),
            endpoint=(
                "unix:///other/docker.sock" if drift == "daemon_endpoint" else daemon.endpoint
            ),
            daemon_id=("OTHER:DAEMON:2" if drift == "daemon_id" else daemon.daemon_id),
        )
    else:
        volumes = _volume_identities()
        inputs["volume_identities_after"] = TrustedTimeVolumeIdentities(
            socket_sha256=("c" * 64 if drift == "socket_volume" else volumes.socket_sha256),
            state_sha256=("d" * 64 if drift == "state_volume" else volumes.state_sha256),
        )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "endpoint",
    [
        "unix:///tmp/../docker.sock",
        "unix:///tmp/./docker.sock",
        "unix:////tmp/docker.sock",
        "unix:///tmp/docker.sock\n",
        "unix:///tmp/docker.sock\x00suffix",
        "unix:///tmp/\x01docker.sock",
        "tcp://127.0.0.1:2375",
    ],
)
def test_created_topology_rejects_noncanonical_or_control_bearing_daemon_endpoint(
    tmp_path: Path,
    endpoint: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    daemon = _daemon_identity()
    inputs["daemon_identity_before"] = LocalDockerDaemonIdentity(
        context_name=daemon.context_name,
        endpoint=endpoint,
        daemon_id=daemon.daemon_id,
    )
    inputs["daemon_identity_after"] = inputs["daemon_identity_before"]

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("field_name", ["context_name", "endpoint", "daemon_id"])
def test_created_topology_rejects_equal_daemon_after_string_subclass(
    tmp_path: Path,
    field_name: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    daemon_after = _daemon_identity()
    object.__setattr__(
        daemon_after,
        field_name,
        _EqualString(cast(str, getattr(daemon_after, field_name))),
    )
    inputs["daemon_identity_after"] = daemon_after

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
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
        (("a" * 63, SUPERVISOR_CONTAINER_ID), ("a" * 63, SUPERVISOR_CONTAINER_ID)),
        (("A" * 64, SUPERVISOR_CONTAINER_ID), ("A" * 64, SUPERVISOR_CONTAINER_ID)),
        (
            (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID),
            (SOURCE_CONTAINER_ID, OTHER_CONTAINER_ID),
        ),
        (
            [SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID],
            [SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID],
        ),
    ],
)
def test_created_topology_rejects_invalid_or_changed_project_inventory(
    tmp_path: Path,
    before: object,
    after: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs["project_container_ids_before"] = before
    inputs["project_container_ids_after"] = after

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "oversized",
        "wrong_type",
        "wrong_keys",
        "key_subclass",
        "key_too_long",
        "key_uppercase",
        "key_nonhex",
        "key_integer",
        "key_id_mismatch",
    ],
)
def test_created_topology_requires_exact_id_keyed_inspection_mapping(
    tmp_path: Path,
    mutation: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    if mutation == "wrong_type":
        inputs["container_inspections"] = []
        with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
            _validate(inputs)
        return
    if mutation == "oversized":
        inputs["container_inspections"] = {f"{index:064x}": None for index in range(1_024)}
        with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
            _validate(inputs)
        return

    inspections = cast(dict[object, object], inputs["container_inspections"])
    if mutation == "missing":
        inspections.pop(SUPERVISOR_CONTAINER_ID)
    elif mutation == "extra":
        inspections[OTHER_CONTAINER_ID] = deepcopy(inspections[SOURCE_CONTAINER_ID])
    elif mutation == "wrong_keys":
        inspections[OTHER_CONTAINER_ID] = inspections.pop(SUPERVISOR_CONTAINER_ID)
    elif mutation == "key_subclass":
        source = inspections.pop(SOURCE_CONTAINER_ID)
        inspections[_EqualString(SOURCE_CONTAINER_ID)] = source
    elif mutation in {"key_too_long", "key_uppercase", "key_nonhex", "key_integer"}:
        source = inspections.pop(SOURCE_CONTAINER_ID)
        replacement: object = {
            "key_too_long": "a" * 65,
            "key_uppercase": "A" * 64,
            "key_nonhex": "g" * 64,
            "key_integer": 1,
        }[mutation]
        inspections[replacement] = source
    else:
        source = cast(list[dict[str, object]], inspections.pop(SOURCE_CONTAINER_ID))
        inspections[SOURCE_CONTAINER_ID] = _mutated_inspection(
            source,
            (0, "Id"),
            OTHER_CONTAINER_ID,
        )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "label", "value"),
    [
        ("source", "com.docker.compose.project", "other-project"),
        ("source", "com.docker.compose.service", "unknown-service"),
        ("source", "com.docker.compose.service", "trusted-time-supervisor"),
        ("supervisor", "com.docker.compose.service", "chrony-nts"),
        ("source", "com.docker.compose.oneoff", "True"),
        ("supervisor", "com.docker.compose.oneoff", False),
        ("source", "com.docker.compose.container-number", "2"),
        ("supervisor", "com.docker.compose.container-number", 1),
    ],
)
def test_created_topology_rejects_project_or_role_label_drift(
    tmp_path: Path,
    role: str,
    label: str,
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[container_id] = _mutated_inspection(
        inspections[container_id],
        (0, "Config", "Labels", label),
        value,
    )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("Status", "running"),
        ("Status", "exited"),
        ("Status", "paused"),
        ("Status", "restarting"),
        ("Status", "dead"),
        ("Running", True),
        ("Running", 0),
        ("Paused", True),
        ("Restarting", True),
        ("OOMKilled", True),
        ("Dead", True),
        ("Pid", 1),
        ("Pid", False),
        ("ExitCode", 1),
        ("ExitCode", False),
        ("Error", "prior start failed"),
        ("StartedAt", "2026-08-09T12:00:00Z"),
        ("FinishedAt", "2026-08-09T12:00:01Z"),
    ],
)
def test_created_topology_rejects_every_non_created_execution_state(
    tmp_path: Path,
    field_name: str,
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[SUPERVISOR_CONTAINER_ID] = _mutated_inspection(
        inspections[SUPERVISOR_CONTAINER_ID],
        (0, "State", field_name),
        value,
    )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("mutation", ["missing_state_key", "extra_state_key", "restart_count"])
def test_created_topology_requires_complete_exact_never_started_state(
    tmp_path: Path,
    mutation: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    supervisor = deepcopy(inspections[SUPERVISOR_CONTAINER_ID])
    if mutation == "restart_count":
        supervisor[0]["RestartCount"] = 1
    else:
        state = cast(dict[str, object], supervisor[0]["State"])
        if mutation == "missing_state_key":
            state.pop("FinishedAt")
        else:
            state["Health"] = {"Status": "healthy"}
    inspections[SUPERVISOR_CONTAINER_ID] = supervisor

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("source", (0, "Image"), SUPERVISOR_IMAGE_ID),
        ("source", (0, "Config", "Image"), SUPERVISOR_IMAGE_ID),
        ("source", (0, "Path"), "/bin/sh"),
        ("source", (0, "Args"), ["-c", "true"]),
        ("source", (0, "Config", "User"), "0:0"),
        ("source", (0, "Config", "Entrypoint"), ["/bin/sh"]),
        ("source", (0, "Config", "Cmd"), ["-c", "true"]),
        ("source", (0, "Config", "WorkingDir"), "/tmp"),
        ("source", (0, "Config", "ExposedPorts"), {"123/udp": {}}),
        ("supervisor", (0, "Image"), SOURCE_IMAGE_ID),
        ("supervisor", (0, "Config", "Image"), SOURCE_IMAGE_ID),
        ("supervisor", (0, "Path"), "/bin/sh"),
        ("supervisor", (0, "Args"), ["--unexpected"]),
        ("supervisor", (0, "Config", "User"), "0:0"),
        ("supervisor", (0, "Config", "Entrypoint"), ["/bin/sh"]),
        ("supervisor", (0, "Config", "Cmd"), ["/bin/true"]),
        ("supervisor", (0, "Config", "WorkingDir"), "/tmp"),
        ("supervisor", (0, "Config", "ExposedPorts"), {"8080/tcp": {}}),
    ],
)
def test_created_topology_rejects_image_or_effective_command_drift(
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[container_id] = _mutated_inspection(inspections[container_id], path, value)

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "mutation"),
    [
        ("source", "missing"),
        ("source", "extra"),
        ("source", "duplicate"),
        ("source", "value"),
        ("supervisor", "missing"),
        ("supervisor", "extra"),
        ("supervisor", "duplicate"),
        ("supervisor", "value"),
    ],
)
def test_created_topology_rejects_environment_allowlist_drift(
    tmp_path: Path,
    role: str,
    mutation: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspection = deepcopy(inspections[container_id])
    configuration = cast(dict[str, object], inspection[0]["Config"])
    environment = cast(list[str], configuration["Env"])
    if mutation == "missing":
        environment.pop()
    elif mutation == "extra":
        environment.append("AQT_TRUSTED_TIME_DATABASE_URL=plaintext-secret-canary")
    elif mutation == "duplicate":
        environment.append(environment[0])
    else:
        environment[0] = "PATH=/unapproved/bin"
    inspections[container_id] = inspection

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected) as captured:
        _validate(inputs)
    assert "plaintext-secret-canary" not in str(captured.value)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ((0, "Config", "Healthcheck"), None),
        ((0, "Config", "Healthcheck", "Test"), ["CMD", "/bin/true"]),
        ((0, "Config", "Healthcheck", "Interval"), 1),
        ((0, "Config", "Healthcheck", "Timeout"), 2),
        ((0, "Config", "Healthcheck", "StartPeriod"), 3),
        ((0, "Config", "Healthcheck", "Retries"), 1),
    ],
)
def test_created_topology_rejects_source_healthcheck_drift(
    tmp_path: Path,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[SOURCE_CONTAINER_ID] = _mutated_inspection(
        inspections[SOURCE_CONTAINER_ID],
        path,
        value,
    )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


def test_created_topology_rejects_supervisor_healthcheck_or_network_drift(
    tmp_path: Path,
) -> None:
    for container_id, path, value in (
        (
            SUPERVISOR_CONTAINER_ID,
            (0, "Config", "Healthcheck"),
            {"Test": ["CMD", "/bin/true"]},
        ),
        (
            SOURCE_CONTAINER_ID,
            (0, "NetworkSettings", "Networks"),
            {COMPOSE_NETWORK_NAME: {}, "other-network": {}},
        ),
        (
            SUPERVISOR_CONTAINER_ID,
            (0, "NetworkSettings", "Networks"),
            {},
        ),
    ):
        inputs = _valid_inputs(tmp_path)
        inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
        inspections[container_id] = _mutated_inspection(
            inspections[container_id],
            path,
            value,
        )
        with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
            _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("source", (0, "HostConfig", "Binds", 0), "other:/var/lib/chrony:rw"),
        ("source", (0, "HostConfig", "Mounts", 0, "Source"), "other-socket"),
        ("source", (0, "HostConfig", "Mounts", 0, "Target"), "/other"),
        ("source", (0, "HostConfig", "Mounts", 0, "VolumeOptions", "NoCopy"), False),
        ("source", (0, "Mounts", 0, "Name"), "other-socket"),
        ("source", (0, "Mounts", 1, "RW"), False),
        ("supervisor", (0, "HostConfig", "Mounts", 1, "Source"), "/other/secret"),
        ("supervisor", (0, "HostConfig", "Mounts", 1, "Target"), "/other"),
        ("supervisor", (0, "HostConfig", "Mounts", 1, "ReadOnly"), False),
        ("supervisor", (0, "HostConfig", "Mounts", 0, "VolumeOptions", "NoCopy"), False),
        ("supervisor", (0, "Mounts", 1, "Destination"), "/other"),
        ("supervisor", (0, "Mounts", 1, "RW"), True),
        ("supervisor", (0, "Mounts", 0, "Name"), "other-socket"),
    ],
)
def test_created_topology_rejects_mount_drift(
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[container_id] = _mutated_inspection(inspections[container_id], path, value)

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("role", ["source", "supervisor"])
@pytest.mark.parametrize("location", ["HostConfig", "Mounts"])
def test_created_topology_rejects_missing_or_extra_mounts(
    tmp_path: Path,
    role: str,
    location: str,
) -> None:
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    for mutation in ("missing", "extra"):
        inputs = _valid_inputs(tmp_path)
        inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
        inspection = deepcopy(inspections[container_id])
        if location == "HostConfig":
            mounts = cast(list[object], cast(dict[str, object], inspection[0][location])["Mounts"])
        else:
            mounts = cast(list[object], inspection[0][location])
        if mutation == "missing":
            mounts.pop()
        else:
            mounts.append(deepcopy(mounts[0]))
        inspections[container_id] = inspection
        with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
            _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("ReadonlyRootfs", False),
        ("CapDrop", []),
        ("CapAdd", ["SYS_TIME"]),
        ("SecurityOpt", []),
        ("Privileged", True),
        ("PidsLimit", 1),
        ("NanoCpus", 0),
        ("Memory", 0),
        ("Init", False),
        ("NetworkMode", "host"),
        ("PublishAllPorts", True),
        ("PortBindings", {"123/udp": [{"HostPort": "123"}]}),
        ("Devices", [{"PathOnHost": "/dev/rtc"}]),
        ("DeviceCgroupRules", ["c 1:3 rwm"]),
        ("Tmpfs", {}),
        ("RestartPolicy", {"MaximumRetryCount": 0, "Name": "always"}),
        ("AutoRemove", True),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("UTSMode", "host"),
        ("GroupAdd", ["0"]),
        ("VolumesFrom", ["other-container:rw"]),
        ("ExtraHosts", ["metadata:169.254.169.254"]),
        ("OomKillDisable", True),
    ],
)
def test_created_topology_rejects_hardening_drift(
    tmp_path: Path,
    field_name: str,
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[SUPERVISOR_CONTAINER_ID] = _mutated_inspection(
        inspections[SUPERVISOR_CONTAINER_ID],
        (0, "HostConfig", field_name),
        value,
    )

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "section", "field_name"),
    [
        ("source", "Config", "ExposedPorts"),
        ("supervisor", "Config", "Entrypoint"),
        ("supervisor", "Config", "ExposedPorts"),
        ("supervisor", "Config", "Healthcheck"),
        ("supervisor", "HostConfig", "Binds"),
        ("supervisor", "HostConfig", "CapAdd"),
        ("supervisor", "HostConfig", "DeviceCgroupRules"),
        ("supervisor", "HostConfig", "DeviceRequests"),
        ("supervisor", "HostConfig", "Devices"),
        ("supervisor", "HostConfig", "Dns"),
        ("supervisor", "HostConfig", "DnsOptions"),
        ("supervisor", "HostConfig", "DnsSearch"),
        ("supervisor", "HostConfig", "ExtraHosts"),
        ("supervisor", "HostConfig", "GroupAdd"),
        ("supervisor", "HostConfig", "Links"),
        ("supervisor", "HostConfig", "PortBindings"),
        ("supervisor", "HostConfig", "VolumesFrom"),
    ],
)
def test_created_topology_rejects_missing_required_nullable_fields(
    tmp_path: Path,
    role: str,
    section: str,
    field_name: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspection = deepcopy(inspections[container_id])
    cast(dict[str, object], inspection[0][section]).pop(field_name)
    inspections[container_id] = inspection

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "neutral_values", "wrong_empty"),
    [
        ("Binds", (None, []), {}),
        ("CapAdd", (None, []), {}),
        ("DeviceCgroupRules", (None, []), {}),
        ("DeviceRequests", (None, []), {}),
        ("Devices", (None, []), {}),
        ("Dns", (None, []), {}),
        ("DnsOptions", (None, []), {}),
        ("DnsSearch", (None, []), {}),
        ("ExtraHosts", (None, []), {}),
        ("GroupAdd", (None, []), {}),
        ("Links", (None, []), {}),
        ("PortBindings", (None, {}), []),
        ("VolumesFrom", (None, []), {}),
    ],
)
def test_created_topology_accepts_only_reviewed_nullable_neutral_shapes(
    tmp_path: Path,
    field_name: str,
    neutral_values: tuple[object, object],
    wrong_empty: object,
) -> None:
    for neutral in neutral_values:
        inputs = _valid_inputs(tmp_path)
        inspections = cast(
            dict[str, list[dict[str, object]]],
            inputs["container_inspections"],
        )
        host = cast(dict[str, object], inspections[SUPERVISOR_CONTAINER_ID][0]["HostConfig"])
        host[field_name] = neutral
        _validate(inputs)

    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    host = cast(dict[str, object], inspections[SUPERVISOR_CONTAINER_ID][0]["HostConfig"])
    host[field_name] = wrong_empty
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize("accepted", [None, False])
def test_created_topology_accepts_explicit_neutral_oom_policy(
    tmp_path: Path,
    accepted: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    host = cast(dict[str, object], inspections[SUPERVISOR_CONTAINER_ID][0]["HostConfig"])
    host["OomKillDisable"] = accepted
    _validate(inputs)


@pytest.mark.parametrize("rejected", [0, True])
def test_created_topology_rejects_numeric_or_enabled_oom_policy(
    tmp_path: Path,
    rejected: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    host = cast(dict[str, object], inspections[SUPERVISOR_CONTAINER_ID][0]["HostConfig"])
    host["OomKillDisable"] = rejected
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("section", "path", "value"),
    [
        ("Config", ("StopSignal",), "SIGKILL"),
        ("Config", ("NetworkDisabled",), True),
        ("HostConfig", ("DeviceRequests",), [{"Capabilities": [["gpu"]]}]),
        ("HostConfig", ("CgroupnsMode",), "host"),
        ("HostConfig", ("UsernsMode",), "host"),
        ("HostConfig", ("Cgroup",), "unreviewed-parent"),
        ("HostConfig", ("LogConfig", "Type"), "syslog"),
        ("HostConfig", ("LogConfig", "Config"), {"max-size": "10m"}),
        ("HostConfig", ("Dns",), ["8.8.8.8"]),
        ("HostConfig", ("DnsOptions",), ["use-vc"]),
        ("HostConfig", ("DnsSearch",), ["example.test"]),
        ("HostConfig", ("Links",), ["other:database"]),
        ("HostConfig", ("Sysctls",), {"net.ipv4.ip_forward": "1"}),
        ("HostConfig", ("MaskedPaths",), MASKED_PATHS[1:]),
        ("HostConfig", ("ReadonlyPaths",), READONLY_PATHS[1:]),
    ],
)
def test_created_topology_rejects_extended_runtime_boundary_drift(
    tmp_path: Path,
    section: str,
    path: tuple[str, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    full_path: tuple[str | int, ...] = (0, section, *path)
    inspections[SUPERVISOR_CONTAINER_ID] = _mutated_inspection(
        inspections[SUPERVISOR_CONTAINER_ID],
        full_path,
        value,
    )
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("source", (0, "HostConfig", "PidsLimit"), 32.0),
        ("source", (0, "HostConfig", "NanoCpus"), 250_000_000.0),
        ("source", (0, "HostConfig", "Memory"), 67_108_864.0),
        (
            "source",
            (0, "HostConfig", "RestartPolicy", "MaximumRetryCount"),
            False,
        ),
        ("source", (0, "Config", "Healthcheck", "Interval"), 2_000_000_000.0),
        ("source", (0, "Config", "Healthcheck", "Retries"), 15.0),
        ("supervisor", (0, "HostConfig", "PidsLimit"), 64.0),
        ("supervisor", (0, "HostConfig", "NanoCpus"), 500_000_000.0),
        ("supervisor", (0, "HostConfig", "Memory"), 268_435_456.0),
        (
            "supervisor",
            (0, "HostConfig", "RestartPolicy", "MaximumRetryCount"),
            False,
        ),
    ],
)
def test_created_topology_rejects_float_or_bool_numeric_confusion(
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    container_id = SOURCE_CONTAINER_ID if role == "source" else SUPERVISOR_CONTAINER_ID
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[container_id] = _mutated_inspection(inspections[container_id], path, value)
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
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
@pytest.mark.parametrize("invalid", [None, Path("relative/input"), Path("/different/input")])
def test_created_topology_requires_all_exact_absolute_staged_paths(
    tmp_path: Path,
    field_name: str,
    invalid: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs[field_name] = invalid

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "invalid",
    [
        Path("/"),
        Path("//private/autoquant/input"),
        Path("/private/autoquant/../input"),
        Path("/private/autoquant/input\nname"),
        Path("/private/autoquant/input\x00name"),
        Path("/private/autoquant/input\x7fname"),
    ],
)
def test_created_topology_rejects_nonconcrete_or_noncanonical_staged_paths(
    tmp_path: Path,
    invalid: Path,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs["expected_database_secret_file"] = invalid
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


def test_created_topology_requires_four_distinct_staged_paths(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    shared_path = tmp_path / "one-shared-input"
    for field_name in (
        "expected_database_secret_file",
        "expected_head_anchor_authority_file",
        "expected_head_anchor_auth_secret_file",
        "expected_head_anchor_signing_key_secret_file",
    ):
        inputs[field_name] = shared_path
    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    supervisor = inspections[SUPERVISOR_CONTAINER_ID][0]
    host_mounts = cast(
        list[dict[str, object]], cast(dict[str, object], supervisor["HostConfig"])["Mounts"]
    )
    runtime_mounts = cast(list[dict[str, object]], supervisor["Mounts"])
    for mount in host_mounts[1:]:
        mount["Source"] = str(shared_path)
    for mount in runtime_mounts[1:]:
        mount["Source"] = str(shared_path)

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


def test_created_topology_snapshot_isolated_copy_and_digest_are_stable(tmp_path: Path) -> None:
    inputs = _valid_inputs(tmp_path)
    snapshot = _validate(inputs)
    original_payload = snapshot.payload()
    original_digest = snapshot.snapshot_sha256

    inspections = cast(dict[str, list[dict[str, object]]], inputs["container_inspections"])
    inspections[SOURCE_CONTAINER_ID][0]["Image"] = "sha256:" + "f" * 64
    cast(dict[str, object], inputs["source_image_configuration"])["User"] = "0:0"
    inputs["project_container_ids_before"] = (OTHER_CONTAINER_ID, OTHER_CONTAINER_ID)

    assert snapshot.payload() == original_payload
    assert snapshot.snapshot_sha256 == original_digest
    encoded = json.dumps(snapshot.payload(), sort_keys=True)
    assert str(tmp_path) not in encoded
    assert "Env" not in encoded
    assert "Mounts" not in encoded
    assert "State" not in encoded


def test_equivalent_mapping_and_inventory_order_have_identical_digest(tmp_path: Path) -> None:
    baseline_inputs = _valid_inputs(tmp_path / "same")
    reordered_inputs = _valid_inputs(
        tmp_path / "same",
        reverse_inventory_before=True,
        reverse_inventory_after=True,
        reverse_inspections=True,
    )
    for field_name in ("source_image_configuration", "supervisor_image_configuration"):
        configuration = cast(dict[str, object], reordered_inputs[field_name])
        reordered_inputs[field_name] = dict(reversed(tuple(configuration.items())))

    baseline = _validate(baseline_inputs)
    reordered = _validate(reordered_inputs)

    assert reordered == baseline
    assert reordered.payload() == baseline.payload()
    assert reordered.snapshot_sha256 == baseline.snapshot_sha256


@pytest.mark.parametrize("unsupported", [b"not-json", float("nan"), {1, 2}, ("tuple",)])
def test_created_topology_rejects_unsupported_non_json_configuration_values(
    tmp_path: Path,
    unsupported: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    configuration = cast(dict[str, object], inputs["source_image_configuration"])
    configuration["Unsupported"] = unsupported

    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


def test_created_topology_rejects_cyclic_and_oversize_projections(tmp_path: Path) -> None:
    cyclic_inputs = _valid_inputs(tmp_path)
    cyclic_configuration = cast(dict[str, object], cyclic_inputs["source_image_configuration"])
    cyclic_configuration["cycle"] = cyclic_configuration
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(cyclic_inputs)

    oversize_inputs = _valid_inputs(tmp_path)
    oversize_configuration = cast(dict[str, object], oversize_inputs["source_image_configuration"])
    oversize_configuration["oversize"] = "x" * (4 * 1_024 * 1_024 + 1)
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(oversize_inputs)


def test_created_topology_rejects_json_depth_and_node_budget_exhaustion(tmp_path: Path) -> None:
    depth_inputs = _valid_inputs(tmp_path)
    depth_configuration = cast(dict[str, object], depth_inputs["source_image_configuration"])
    nested: object = None
    for _ in range(66):
        nested = [nested]
    depth_configuration["deep"] = nested
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(depth_inputs)

    node_inputs = _valid_inputs(tmp_path)
    node_configuration = cast(dict[str, object], node_inputs["source_image_configuration"])
    node_configuration["many"] = [None] * 131_073
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(node_inputs)


def test_json_mapping_cardinality_fails_before_iterating_children() -> None:
    mapping = {f"key-{index}": None for index in range(_MAXIMUM_JSON_PROJECTION_NODES // 2)}
    remaining_nodes = [_MAXIMUM_JSON_PROJECTION_NODES]
    remaining_ascii_bytes = [_MAXIMUM_JSON_PROJECTION_BYTES]

    with pytest.raises(ValueError):
        _require_exact_json_tree(
            mapping,
            remaining_nodes=remaining_nodes,
            remaining_ascii_bytes=remaining_ascii_bytes,
        )

    assert remaining_nodes == [_MAXIMUM_JSON_PROJECTION_NODES - 1]
    assert remaining_ascii_bytes == [_MAXIMUM_JSON_PROJECTION_BYTES]


@pytest.mark.parametrize(
    "value",
    [
        1 << 257,
        "é" * ((4 * 1_024 * 1_024) // 6 + 1),
    ],
)
def test_created_topology_rejects_pre_serialization_allocation_budget_inputs(
    tmp_path: Path,
    value: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    configuration = cast(dict[str, object], inputs["source_image_configuration"])
    configuration["allocation"] = value
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "inspection",
    [
        None,
        {},
        [],
        [[], {}],
        [{}, {}],
        ["not-a-container"],
    ],
)
def test_created_topology_rejects_malformed_container_inspection_shapes(
    tmp_path: Path,
    inspection: object,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inspections[SOURCE_CONTAINER_ID] = inspection
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("context_name", ""),
        ("context_name", "bad/context"),
        ("context_name", "context\nname"),
        ("context_name", "x" * 257),
        ("daemon_id", ""),
        ("daemon_id", "daemon\nid"),
        ("daemon_id", "x" * 257),
    ],
)
def test_created_topology_rejects_malformed_daemon_context_or_id(
    tmp_path: Path,
    field_name: str,
    value: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    daemon = _daemon_identity()
    malformed = LocalDockerDaemonIdentity(
        context_name=(value if field_name == "context_name" else daemon.context_name),
        endpoint=daemon.endpoint,
        daemon_id=(value if field_name == "daemon_id" else daemon.daemon_id),
    )
    inputs["daemon_identity_before"] = malformed
    inputs["daemon_identity_after"] = malformed
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    "field_name",
    [
        "approval",
        "approved_launch",
        "daemon_identity_after",
        "volume_identities_before",
        "volume_identities_after",
        "container_inspections",
        "source_image_configuration",
        "supervisor_image_configuration",
    ],
)
def test_created_topology_rejects_wrong_exact_input_types(
    tmp_path: Path,
    field_name: str,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs[field_name] = object()
    with pytest.raises(TrustedTimePostEnrollmentCreatedTopologyRejected):
        _validate(inputs)


def test_created_topology_validation_performs_no_execution_claim_or_release_mutation(
    tmp_path: Path,
) -> None:
    inputs = _valid_inputs(tmp_path)
    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=AssertionError("Docker must not run"),
        ) as docker,
        patch(
            "scripts.start_trusted_time_supervisor.run_bounded_subprocess",
            side_effect=AssertionError("subprocess must not run"),
        ) as subprocess_runner,
        patch(
            "scripts.trusted_time_post_enrollment_start.retain_post_enrollment_start_claim",
            side_effect=AssertionError("claim must not be retained"),
        ) as retain_claim,
        patch(
            "apps.trusted_time_supervisor.post_enrollment_release.write_post_enrollment_start_release",
            side_effect=AssertionError("release must not be published"),
        ) as release,
    ):
        snapshot = _validate(inputs)

    assert snapshot.status == POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS
    docker.assert_not_called()
    subprocess_runner.assert_not_called()
    retain_claim.assert_not_called()
    release.assert_not_called()
    assert list(tmp_path.iterdir()) == []
