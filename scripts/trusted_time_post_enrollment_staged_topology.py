"""Pure binding for one caller-supplied staged, unreleased topology.

This module performs no I/O, reads no clock, starts no process, retains no
claim, and grants no authority.  It validates already-decoded candidates for
the state after both exact containers are running but before the supervisor's
fixed release marker exists.  A future bounded Docker reader must establish
the candidates' provenance and reject duplicate keys in the raw JSON bytes.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from apps.trusted_time_supervisor.main import DATABASE_SECRET_CONSUMED_BYTES
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeImmutableLaunchEvidence,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_SERVICE,
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.start_trusted_time_supervisor import (
    DATABASE_SECRET_CONSUMED_PATH,
    DATABASE_SECRET_CONSUMED_SHA256,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
    validate_exact_staged_running_container,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    _is_post_enrollment_created_topology_network_name,
    _is_uuid4,
    _isolated_json_projection,
    _valid_daemon_identity,
    _validated_container_inventory,
)

POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-staged-unreleased-topology-snapshot-v1"
)
POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS = "staged_unreleased_topology_snapshot_unqualified"

_SOURCE_SERVICE = "chrony-nts"
_SUPERVISOR_SERVICE = "trusted-time-supervisor"
_SERVICES = frozenset({_SOURCE_SERVICE, _SUPERVISOR_SERVICE})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_MAXIMUM_FILESYSTEM_IDENTITY_INTEGER_BITS = 256
_RUNTIME_STATE_FIELDS = (
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
)


def _authority_is_never_granted(_: object) -> bool:
    return False


class TrustedTimePostEnrollmentStagedTopologyRejected(ValueError):
    """The submitted staged, unreleased topology could not be bound."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _is_exact_int(value: object, *, minimum: int = 0) -> bool:
    return (
        type(value) is int
        and value >= minimum
        and value.bit_length() <= _MAXIMUM_FILESYSTEM_IDENTITY_INTEGER_BITS
    )


def _is_absolute_lexically_canonical_string(value: object) -> bool:
    if type(value) is not str or not value or len(value) > 4_096:
        return False
    if value.startswith("//") or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        return False
    try:
        path = Path(value)
        return path.is_absolute() and path == Path(os.path.abspath(value)) and str(path) == value
    except (OSError, TypeError, ValueError):
        return False


def _is_absolute_lexically_canonical_path(value: object) -> bool:
    return type(value) is type(Path()) and _is_absolute_lexically_canonical_string(os.fspath(value))


def _payload_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentConsumedMarkerCandidate:
    """Caller-supplied stable identity for the fixed consumed-secret marker."""

    path: str
    byte_sha256: str
    size: int
    owner_uid: int
    owner_gid: int
    mode: int
    link_count: int
    regular: bool
    device: int
    inode: int
    modified_time_ns: int
    changed_time_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or self.path != DATABASE_SECRET_CONSUMED_PATH
            or type(self.byte_sha256) is not str
            or self.byte_sha256 != DATABASE_SECRET_CONSUMED_SHA256
            or type(self.size) is not int
            or self.size != len(DATABASE_SECRET_CONSUMED_BYTES)
            or type(self.owner_uid) is not int
            or self.owner_uid != 10_001
            or type(self.owner_gid) is not int
            or self.owner_gid != 10_001
            or type(self.mode) is not int
            or self.mode != 0o400
            or type(self.link_count) is not int
            or self.link_count != 1
            or self.regular is not True
            or not _is_exact_int(self.device)
            or not _is_exact_int(self.inode, minimum=1)
            or not _is_exact_int(self.modified_time_ns)
            or not _is_exact_int(self.changed_time_ns)
        ):
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time consumed-marker candidate is invalid"
            )

    def payload(self) -> dict[str, object]:
        return {
            "byte_sha256": self.byte_sha256,
            "changed_time_ns": self.changed_time_ns,
            "device": self.device,
            "inode": self.inode,
            "link_count": self.link_count,
            "mode": self.mode,
            "modified_time_ns": self.modified_time_ns,
            "owner_gid": self.owner_gid,
            "owner_uid": self.owner_uid,
            "path": self.path,
            "regular": self.regular,
            "size": self.size,
            "status": "present",
        }

    @property
    def candidate_sha256(self) -> str:
        return _payload_sha256(self.payload())


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentAbsentPathCandidate:
    """Caller-supplied exact absence result for one canonical path."""

    path: str
    status: str = "absent"

    def __post_init__(self) -> None:
        if (
            not _is_absolute_lexically_canonical_string(self.path)
            or type(self.status) is not str
            or self.status != "absent"
        ):
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time absent-path candidate is invalid"
            )

    def payload(self) -> dict[str, str]:
        return {"path": self.path, "status": self.status}


def _validated_absence_candidates(
    before: object,
    after: object,
    *,
    expected_paths: frozenset[str],
    label: str,
) -> tuple[tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...], str]:
    if (
        type(before) is not tuple
        or type(after) is not tuple
        or len(before) != len(expected_paths)
        or len(after) != len(expected_paths)
        or any(type(value) is not TrustedTimePostEnrollmentAbsentPathCandidate for value in before)
        or any(type(value) is not TrustedTimePostEnrollmentAbsentPathCandidate for value in after)
    ):
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            f"trusted-time {label} candidates are invalid"
        )
    try:
        for value in (*before, *after):
            cast(TrustedTimePostEnrollmentAbsentPathCandidate, value).__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            f"trusted-time {label} candidates are invalid"
        ) from None
    before_by_path = {
        cast(TrustedTimePostEnrollmentAbsentPathCandidate, value).path: cast(
            TrustedTimePostEnrollmentAbsentPathCandidate, value
        )
        for value in before
    }
    after_by_path = {
        cast(TrustedTimePostEnrollmentAbsentPathCandidate, value).path: cast(
            TrustedTimePostEnrollmentAbsentPathCandidate, value
        )
        for value in after
    }
    if (
        set(before_by_path) != expected_paths
        or set(after_by_path) != expected_paths
        or len(before_by_path) != len(before)
        or len(after_by_path) != len(after)
        or before_by_path != after_by_path
    ):
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            f"trusted-time {label} candidates changed"
        )
    ordered = tuple(before_by_path[path] for path in sorted(before_by_path))
    return ordered, _payload_sha256([candidate.payload() for candidate in ordered])


def _inspection_container(inspection: object) -> dict[str, object]:
    if type(inspection) is not list or len(inspection) != 1 or type(inspection[0]) is not dict:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container inspection is invalid"
        )
    return cast(dict[str, object], inspection[0])


def _inspection_role(container_id: str, inspection: object) -> str:
    container = _inspection_container(inspection)
    configuration = container.get("Config")
    if type(configuration) is not dict:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container role is invalid"
        )
    labels = configuration.get("Labels")
    if type(labels) is not dict:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container role is invalid"
        )
    service = labels.get("com.docker.compose.service")
    if (
        container.get("Id") != container_id
        or labels.get("com.docker.compose.project")
        != POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
        or service not in _SERVICES
    ):
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container role is invalid"
        )
    return cast(str, service)


def _normalized_running_state(
    container: dict[str, object],
    *,
    expected_service: str,
) -> dict[str, object]:
    state = container.get("State")
    if type(state) is not dict:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container state is invalid"
        )
    try:
        projection: dict[str, object] = {
            field_name: state[field_name] for field_name in _RUNTIME_STATE_FIELDS
        }
    except KeyError:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container state is incomplete"
        ) from None
    if expected_service == _SOURCE_SERVICE:
        health = state.get("Health")
        if type(health) is not dict:
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time staged source health is invalid"
            )
        # Docker appends time-bearing health-log records while the source runs.
        # The exact staged validator checks them, but they are intentionally not
        # part of the stable pre-claim/pre-release topology fingerprint.
        projection["Health"] = {key: value for key, value in health.items() if key != "Log"}
    elif "Health" in state:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged supervisor health is invalid"
        )
    return projection


def _stable_container_projection(
    inspection: object,
    *,
    expected_service: str,
) -> tuple[dict[str, object], str, str]:
    container = _inspection_container(inspection)
    required = (
        "Args",
        "Config",
        "HostConfig",
        "Id",
        "Image",
        "Mounts",
        "NetworkSettings",
        "Path",
        "RestartCount",
    )
    try:
        state_projection = _normalized_running_state(
            container,
            expected_service=expected_service,
        )
        stable_projection: dict[str, object] = {
            field_name: container[field_name] for field_name in required
        }
    except KeyError:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged container projection is incomplete"
        ) from None
    stable_projection["State"] = state_projection
    isolated, projection_sha256 = _isolated_json_projection(
        stable_projection,
        expected_type=dict,
    )
    _, state_sha256 = _isolated_json_projection(
        state_projection,
        expected_type=dict,
    )
    return cast(dict[str, object], isolated), projection_sha256, state_sha256


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStagedContainerSnapshot:
    """Stable digest-only projection of one staged running container."""

    service: str
    container_id: str
    image_id: str
    stable_inspection_projection_sha256: str
    running_state_projection_sha256: str
    image_configuration_projection_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.service) is not str
            or self.service not in _SERVICES
            or type(self.container_id) is not str
            or _CONTAINER_ID_PATTERN.fullmatch(self.container_id) is None
            or type(self.image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.image_id) is None
            or not _is_sha256(self.stable_inspection_projection_sha256)
            or not _is_sha256(self.running_state_projection_sha256)
            or not _is_sha256(self.image_configuration_projection_sha256)
        ):
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time staged container snapshot is invalid"
            )

    def payload(self) -> dict[str, str]:
        return {
            "container_id": self.container_id,
            "image_configuration_projection_sha256": (self.image_configuration_projection_sha256),
            "image_id": self.image_id,
            "running_state_projection_sha256": self.running_state_projection_sha256,
            "service": self.service,
            "stable_inspection_projection_sha256": (self.stable_inspection_projection_sha256),
        }


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
    """Non-authorizing stable projection of a staged unreleased topology."""

    operation_id: str
    approval_sha256: str
    review_projection_sha256: str
    confirmed_enrollment_evidence_sha256: str
    approved_launch: TrustedTimeImmutableLaunchEvidence
    created_topology_snapshot_sha256: str
    daemon_context_name: str
    daemon_endpoint: str
    daemon_id: str
    socket_volume_sha256: str
    state_volume_sha256: str
    source: TrustedTimePostEnrollmentStagedContainerSnapshot
    supervisor: TrustedTimePostEnrollmentStagedContainerSnapshot
    database_secret_consumed_candidate_sha256: str
    release_paths_absence_candidate_sha256: str
    staged_input_retirement_candidate_sha256: str

    def __post_init__(self) -> None:
        daemon_identity = LocalDockerDaemonIdentity(
            context_name=self.daemon_context_name,
            endpoint=self.daemon_endpoint,
            daemon_id=self.daemon_id,
        )
        try:
            if (
                type(self.approved_launch) is not TrustedTimeImmutableLaunchEvidence
                or type(self.source) is not TrustedTimePostEnrollmentStagedContainerSnapshot
                or type(self.supervisor) is not TrustedTimePostEnrollmentStagedContainerSnapshot
            ):
                raise ValueError
            self.approved_launch.__post_init__()
            self.source.__post_init__()
            self.supervisor.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time staged topology snapshot is invalid"
            ) from None
        if (
            not _is_uuid4(self.operation_id)
            or not _is_sha256(self.approval_sha256)
            or not _is_sha256(self.review_projection_sha256)
            or not _is_sha256(self.confirmed_enrollment_evidence_sha256)
            or not _is_sha256(self.created_topology_snapshot_sha256)
            or not _valid_daemon_identity(daemon_identity)
            or not _is_sha256(self.socket_volume_sha256)
            or not _is_sha256(self.state_volume_sha256)
            or self.source.service != _SOURCE_SERVICE
            or self.supervisor.service != _SUPERVISOR_SERVICE
            or self.source.container_id == self.supervisor.container_id
            or self.source.image_id != self.approved_launch.source_image_id
            or self.supervisor.image_id != self.approved_launch.supervisor_image_id
            or not _is_sha256(self.database_secret_consumed_candidate_sha256)
            or not _is_sha256(self.release_paths_absence_candidate_sha256)
            or not _is_sha256(self.staged_input_retirement_candidate_sha256)
        ):
            raise TrustedTimePostEnrollmentStagedTopologyRejected(
                "trusted-time staged topology snapshot is invalid"
            )

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS

    def stable_topology_payload(self) -> dict[str, object]:
        return {
            "approval_sha256": self.approval_sha256,
            "approved_launch": self.approved_launch.payload(),
            "compose_project": POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
            "confirmed_enrollment_evidence_sha256": (self.confirmed_enrollment_evidence_sha256),
            "contract_version": POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
            "created_topology_snapshot_sha256": self.created_topology_snapshot_sha256,
            "daemon_identity": {
                "context_name": self.daemon_context_name,
                "daemon_id": self.daemon_id,
                "endpoint": self.daemon_endpoint,
            },
            "database_secret_consumed_candidate_sha256": (
                self.database_secret_consumed_candidate_sha256
            ),
            "operation_id": self.operation_id,
            "release_paths_absence_candidate_sha256": (self.release_paths_absence_candidate_sha256),
            "review_projection_sha256": self.review_projection_sha256,
            "service": POST_ENROLLMENT_START_SERVICE,
            "source_container": self.source.payload(),
            "staged_input_retirement_candidate_sha256": (
                self.staged_input_retirement_candidate_sha256
            ),
            "supervisor_container": self.supervisor.payload(),
            "status": self.status,
            "volume_identities": {
                "socket_sha256": self.socket_volume_sha256,
                "state_sha256": self.state_volume_sha256,
            },
        }

    @property
    def stable_topology_sha256(self) -> str:
        return _payload_sha256(self.stable_topology_payload())

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        }
        payload.update(
            {
                **self.stable_topology_payload(),
                "authority_granted": False,
                "claim_retention_authorized": False,
                "compose_project": POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
                "container_identity_authenticated": False,
                "contract_version": POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
                "created_topology_authenticated": False,
                "daemon_identity_authenticated": False,
                "database_secret_consumption_authenticated": False,
                "database_secret_disclosed": False,
                "inventory_authenticated": False,
                "observation_provenance_authenticated": False,
                "persistent_start_authorized": False,
                "release_absence_authenticated": False,
                "release_authorized": False,
                "sequence_2_authorized": False,
                "service": POST_ENROLLMENT_START_SERVICE,
                "shutdown_authorized": False,
                "source_start_authenticated": False,
                "source_start_authorized": False,
                "stable_topology_sha256": self.stable_topology_sha256,
                "staged_input_retirement_authenticated": False,
                "start_order_authenticated": False,
                "status": self.status,
                "submitted_project_container_count": 2,
                "supervisor_start_authenticated": False,
                "supervisor_start_authorized": False,
                "topology_authenticated": False,
                "topology_mutation_authorized": False,
                "volume_identity_authenticated": False,
            }
        )
        return payload

    @property
    def snapshot_sha256(self) -> str:
        return _payload_sha256(self.payload())

    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    inventory_authenticated = property(_authority_is_never_granted)
    observation_provenance_authenticated = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_absence_authenticated = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authenticated = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    staged_input_retirement_authenticated = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    supervisor_start_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    volume_identity_authenticated = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)


def validate_post_enrollment_start_staged_unreleased_topology(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    approved_launch: TrustedTimeApprovedLaunch,
    created_topology: TrustedTimePostEnrollmentCreatedTopologySnapshot,
    daemon_identity_before: LocalDockerDaemonIdentity,
    daemon_identity_after: LocalDockerDaemonIdentity,
    volume_identities_before: TrustedTimeVolumeIdentities,
    volume_identities_after: TrustedTimeVolumeIdentities,
    project_container_ids_before: tuple[str, ...],
    project_container_ids_after: tuple[str, ...],
    container_inspections: dict[str, object],
    source_image_configuration: dict[str, object],
    supervisor_image_configuration: dict[str, object],
    expected_network_name: str,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
    database_secret_consumed_before: TrustedTimePostEnrollmentConsumedMarkerCandidate,
    database_secret_consumed_after: TrustedTimePostEnrollmentConsumedMarkerCandidate,
    release_path_absences_before: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    release_path_absences_after: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    staged_input_retirements_before: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    staged_input_retirements_after: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
) -> TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
    """Bind a caller-supplied staged candidate without executing an action."""

    try:
        if (
            type(approval) is not TrustedTimePostEnrollmentStartApproval
            or type(approved_launch) is not TrustedTimeApprovedLaunch
            or type(created_topology) is not TrustedTimePostEnrollmentCreatedTopologySnapshot
            or type(database_secret_consumed_before)
            is not TrustedTimePostEnrollmentConsumedMarkerCandidate
            or type(database_secret_consumed_after)
            is not TrustedTimePostEnrollmentConsumedMarkerCandidate
        ):
            raise ValueError
        approval.__post_init__()
        approved_launch.__post_init__()
        created_topology.__post_init__()
        database_secret_consumed_before.__post_init__()
        database_secret_consumed_after.__post_init__()

        proposed_launch = approval.proposed_launch
        if (
            created_topology.operation_id != approval.operation_id
            or created_topology.approval_sha256 != approval.approval_sha256
            or created_topology.review_projection_sha256 != approval.review.projection_sha256
            or created_topology.confirmed_enrollment_evidence_sha256
            != approval.confirmed_enrollment.evidence_sha256
            or created_topology.approved_launch != proposed_launch
            or proposed_launch.git_revision != approved_launch.git_revision
            or proposed_launch.image_admission_sha256 != approved_launch.image_admission_sha256
            or proposed_launch.source_image_id != approved_launch.source_image_id
            or proposed_launch.supervisor_image_id != approved_launch.supervisor_image_id
            or not _valid_daemon_identity(daemon_identity_before)
            or not _valid_daemon_identity(daemon_identity_after)
            or daemon_identity_after != daemon_identity_before
            or created_topology.daemon_context_name != daemon_identity_before.context_name
            or created_topology.daemon_endpoint != daemon_identity_before.endpoint
            or created_topology.daemon_id != daemon_identity_before.daemon_id
            or type(volume_identities_before) is not TrustedTimeVolumeIdentities
            or type(volume_identities_after) is not TrustedTimeVolumeIdentities
            or not _is_post_enrollment_created_topology_network_name(expected_network_name)
        ):
            raise ValueError
        volume_identities_before.__post_init__()
        volume_identities_after.__post_init__()
        if (
            volume_identities_after != volume_identities_before
            or created_topology.socket_volume_sha256 != volume_identities_before.socket_sha256
            or created_topology.state_volume_sha256 != volume_identities_before.state_sha256
        ):
            raise ValueError

        inventory_before = _validated_container_inventory(project_container_ids_before)
        inventory_after = _validated_container_inventory(project_container_ids_after)
        created_inventory = frozenset(
            {
                created_topology.source.container_id,
                created_topology.supervisor.container_id,
            }
        )
        if (
            inventory_before != inventory_after
            or inventory_before != created_inventory
            or type(container_inspections) is not dict
            or len(container_inspections) != len(inventory_before)
            or any(type(container_id) is not str for container_id in container_inspections)
            or set(container_inspections) != set(inventory_before)
        ):
            raise ValueError

        staged_paths = (
            expected_database_secret_file,
            expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file,
        )
        if (
            not all(_is_absolute_lexically_canonical_path(path) for path in staged_paths)
            or len(set(staged_paths)) != 4
        ):
            raise ValueError
        expected_staged_path_strings = frozenset(os.fspath(path) for path in staged_paths)
        _, release_absence_sha256 = _validated_absence_candidates(
            release_path_absences_before,
            release_path_absences_after,
            expected_paths=frozenset(
                {
                    POST_ENROLLMENT_START_RELEASE_PATH,
                    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
                }
            ),
            label="release-path absence",
        )
        _, staged_retirement_sha256 = _validated_absence_candidates(
            staged_input_retirements_before,
            staged_input_retirements_after,
            expected_paths=expected_staged_path_strings,
            label="staged-input retirement",
        )
        if database_secret_consumed_before != database_secret_consumed_after:
            raise ValueError

        isolated_source_configuration, source_configuration_sha256 = _isolated_json_projection(
            source_image_configuration,
            expected_type=dict,
        )
        isolated_supervisor_configuration, supervisor_configuration_sha256 = (
            _isolated_json_projection(
                supervisor_image_configuration,
                expected_type=dict,
            )
        )
        if (
            source_configuration_sha256
            != created_topology.source.image_configuration_projection_sha256
            or supervisor_configuration_sha256
            != created_topology.supervisor.image_configuration_projection_sha256
        ):
            raise ValueError
        source_configuration = cast(dict[str, object], isolated_source_configuration)
        supervisor_configuration = cast(dict[str, object], isolated_supervisor_configuration)

        roles: dict[str, tuple[str, object]] = {}
        for container_id, submitted_inspection in container_inspections.items():
            isolated_inspection, _ = _isolated_json_projection(
                submitted_inspection,
                expected_type=list,
            )
            service = _inspection_role(container_id, isolated_inspection)
            if service in roles:
                raise ValueError
            roles[service] = (container_id, isolated_inspection)
        if set(roles) != _SERVICES:
            raise ValueError

        source_id, source_inspection = roles[_SOURCE_SERVICE]
        supervisor_id, supervisor_inspection = roles[_SUPERVISOR_SERVICE]
        if (
            source_id != created_topology.source.container_id
            or supervisor_id != created_topology.supervisor.container_id
            or created_topology.source.image_id != approved_launch.source_image_id
            or created_topology.supervisor.image_id != approved_launch.supervisor_image_id
        ):
            raise ValueError

        validate_exact_staged_running_container(
            source_inspection,
            expected_container_id=source_id,
            expected_image_id=approved_launch.source_image_id,
            expected_image_configuration=source_configuration,
            expected_service=_SOURCE_SERVICE,
            expected_network_name=expected_network_name,
        )
        validate_exact_staged_running_container(
            supervisor_inspection,
            expected_container_id=supervisor_id,
            expected_image_id=approved_launch.supervisor_image_id,
            expected_image_configuration=supervisor_configuration,
            expected_service=_SUPERVISOR_SERVICE,
            expected_network_name=expected_network_name,
            expected_database_secret_file=expected_database_secret_file,
            expected_head_anchor_authority_file=expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file=(
                expected_head_anchor_signing_key_secret_file
            ),
        )

        _, source_projection_sha256, source_state_sha256 = _stable_container_projection(
            source_inspection,
            expected_service=_SOURCE_SERVICE,
        )
        _, supervisor_projection_sha256, supervisor_state_sha256 = _stable_container_projection(
            supervisor_inspection,
            expected_service=_SUPERVISOR_SERVICE,
        )
        return TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot(
            operation_id=approval.operation_id,
            approval_sha256=approval.approval_sha256,
            review_projection_sha256=approval.review.projection_sha256,
            confirmed_enrollment_evidence_sha256=(approval.confirmed_enrollment.evidence_sha256),
            approved_launch=proposed_launch,
            created_topology_snapshot_sha256=created_topology.snapshot_sha256,
            daemon_context_name=daemon_identity_before.context_name,
            daemon_endpoint=daemon_identity_before.endpoint,
            daemon_id=daemon_identity_before.daemon_id,
            socket_volume_sha256=volume_identities_before.socket_sha256,
            state_volume_sha256=volume_identities_before.state_sha256,
            source=TrustedTimePostEnrollmentStagedContainerSnapshot(
                service=_SOURCE_SERVICE,
                container_id=source_id,
                image_id=approved_launch.source_image_id,
                stable_inspection_projection_sha256=source_projection_sha256,
                running_state_projection_sha256=source_state_sha256,
                image_configuration_projection_sha256=source_configuration_sha256,
            ),
            supervisor=TrustedTimePostEnrollmentStagedContainerSnapshot(
                service=_SUPERVISOR_SERVICE,
                container_id=supervisor_id,
                image_id=approved_launch.supervisor_image_id,
                stable_inspection_projection_sha256=(supervisor_projection_sha256),
                running_state_projection_sha256=supervisor_state_sha256,
                image_configuration_projection_sha256=(supervisor_configuration_sha256),
            ),
            database_secret_consumed_candidate_sha256=(
                database_secret_consumed_before.candidate_sha256
            ),
            release_paths_absence_candidate_sha256=release_absence_sha256,
            staged_input_retirement_candidate_sha256=staged_retirement_sha256,
        )
    except TrustedTimePostEnrollmentStagedTopologyRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentStagedTopologyRejected(
            "trusted-time staged unreleased topology snapshot was rejected"
        ) from None


__all__ = [
    "POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION",
    "POST_ENROLLMENT_STAGED_TOPOLOGY_STATUS",
    "TrustedTimePostEnrollmentAbsentPathCandidate",
    "TrustedTimePostEnrollmentConsumedMarkerCandidate",
    "TrustedTimePostEnrollmentStagedContainerSnapshot",
    "TrustedTimePostEnrollmentStagedTopologyRejected",
    "TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot",
    "validate_post_enrollment_start_staged_unreleased_topology",
]
