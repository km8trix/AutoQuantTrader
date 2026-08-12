"""Pure binding for one caller-supplied persistent trusted-time topology.

This module performs no I/O, reads no clock, starts no process, contacts no
database or provider, and grants no authority.  It accepts only already-
decoded candidates for the state after the exact release marker and one exact
sequence-two successor exist.  Observation provenance belongs to a later
bounded reader/controller seam.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_BYTES,
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_RELEASE_SHA256,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeImmutableLaunchEvidence,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_SERVICE,
    TrustedTimePostEnrollmentStartSuccessor,
)
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
    validate_exact_staged_running_container,
)
from scripts.trusted_time_post_enrollment_action_topology_fence import (
    TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
    _claimed_action_fence_payload,
    _valid_claimed_action_fence_capability,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
    _admission_payload,
    _valid_active_controller_admission_capability,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    TrustedTimePostEnrollmentAbsentPathCandidate,
    TrustedTimePostEnrollmentConsumedMarkerCandidate,
    TrustedTimePostEnrollmentStagedContainerSnapshot,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    _inspection_role,
    _is_absolute_lexically_canonical_path,
    _stable_container_projection,
    _validated_absence_candidates,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
    _isolated_json_projection,
    _valid_daemon_identity,
    _validated_container_inventory,
)

POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-persistent-topology-snapshot-v1"
)
POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS = "persistent_topology_snapshot_unqualified"

_SOURCE_SERVICE = "chrony-nts"
_SUPERVISOR_SERVICE = "trusted-time-supervisor"
_SERVICES = frozenset({_SOURCE_SERVICE, _SUPERVISOR_SERVICE})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_FULL_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAC_ADDRESS_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_MAXIMUM_FILESYSTEM_IDENTITY_INTEGER_BITS = 256
_NETWORK_KEYS = frozenset(
    {
        "Attachable",
        "ConfigOnly",
        "ConfigFrom",
        "Containers",
        "Created",
        "Driver",
        "EnableIPv6",
        "IPAM",
        "Id",
        "Ingress",
        "Internal",
        "Labels",
        "Name",
        "Options",
        "Scope",
    }
)
_NETWORK_CONTAINER_KEYS = frozenset(
    {"EndpointID", "IPv4Address", "IPv6Address", "MacAddress", "Name"}
)
_CLOSED_FIELDS = (
    "active_controller_authorized",
    "authority_granted",
    "claim_retention_authorized",
    "container_identity_authenticated",
    "controller_execution_authorized",
    "created_topology_authenticated",
    "current_daemon_session_authenticated",
    "current_lock_session_authenticated",
    "daemon_identity_authenticated",
    "database_secret_consumption_authenticated",
    "database_secret_disclosed",
    "freshness_authenticated",
    "inventory_authenticated",
    "network_identity_authenticated",
    "observation_provenance_authenticated",
    "outcome_retention_authorized",
    "persistent_start_authorized",
    "persistent_start_confirmed",
    "qualified",
    "release_absence_authenticated",
    "release_attempted",
    "release_authorized",
    "release_confirmed",
    "release_marker_authenticated",
    "runtime_start_authorized",
    "runtime_start_confirmed",
    "sequence_2_authorized",
    "sequence_2_confirmed",
    "shutdown_authorized",
    "source_start_authenticated",
    "source_start_authorized",
    "staged_input_retirement_authenticated",
    "start_order_authenticated",
    "success_outcome_retained",
    "success_outcome_retention_authorized",
    "supervisor_start_authenticated",
    "supervisor_start_authorized",
    "topology_authenticated",
    "topology_mutation_authorized",
    "topology_qualified",
    "volume_identity_authenticated",
)


class TrustedTimePostEnrollmentPersistentTopologyRejected(ValueError):
    """The submitted post-release topology could not be bound exactly."""


def _authority_is_never_granted(_: object) -> bool:
    return False


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _is_exact_int(value: object, *, minimum: int = 0) -> bool:
    return (
        type(value) is int
        and value >= minimum
        and value.bit_length() <= _MAXIMUM_FILESYSTEM_IDENTITY_INTEGER_BITS
    )


def _payload_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentReleaseMarkerCandidate:
    """Caller-supplied stable identity for the exact fixed release marker."""

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
            or self.path != POST_ENROLLMENT_START_RELEASE_PATH
            or type(self.byte_sha256) is not str
            or self.byte_sha256 != POST_ENROLLMENT_START_RELEASE_SHA256
            or type(self.size) is not int
            or self.size != len(POST_ENROLLMENT_START_RELEASE_BYTES)
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
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time release-marker candidate is invalid"
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


def _closed_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update({field_name: False for field_name in _CLOSED_FIELDS})
    return payload


def _successor_sha256(successor: TrustedTimePostEnrollmentStartSuccessor) -> str:
    return _payload_sha256(successor.payload())


def _validated_action_fence_sha256(
    candidate: object,
) -> tuple[str, TrustedTimePostEnrollmentStartClaimedActionTopologyFence]:
    if type(candidate) is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
        raise TrustedTimePostEnrollmentPersistentTopologyRejected(
            "trusted-time persistent action-fence baseline is invalid"
        )
    action_fence = candidate
    material = _claimed_action_fence_payload(
        operation_id=action_fence.operation_id,
        approval_sha256=action_fence.approval_sha256,
        session_sha256=action_fence.session_sha256,
        claim_sha256=action_fence.claim_sha256,
        retained_claim_artifact_sha256=action_fence.retained_claim_artifact_sha256,
        claimed_fence_sha256=action_fence.claimed_fence_sha256,
        predecessor_observation_sha256=action_fence.predecessor_observation_sha256,
        final_action_observation_sha256=action_fence.final_action_observation_sha256,
        final_action_snapshot_sha256=action_fence.final_action_snapshot_sha256,
        final_action_stable_topology_sha256=(action_fence.final_action_stable_topology_sha256),
    )
    if not _valid_claimed_action_fence_capability(
        action_fence._capability,
        material,
        action_fence,
    ):
        raise TrustedTimePostEnrollmentPersistentTopologyRejected(
            "trusted-time persistent action-fence baseline is invalid"
        )
    return _payload_sha256(material), action_fence


def _validated_admission_sha256(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
) -> tuple[str, TrustedTimePostEnrollmentStartClaimedActionTopologyFence]:
    action_fence_sha256, action_fence = _validated_action_fence_sha256(admission._action_fence)
    material = _admission_payload(
        operation_id=admission.operation_id,
        approval_sha256=admission.approval_sha256,
        session_sha256=admission.session_sha256,
        claim_sha256=admission.claim_sha256,
        retained_claim_artifact_sha256=admission.retained_claim_artifact_sha256,
        claimed_action_fence_sha256=admission.claimed_action_fence_sha256,
        final_action_observation_sha256=admission.final_action_observation_sha256,
        final_action_snapshot_sha256=admission.final_action_snapshot_sha256,
        final_action_stable_topology_sha256=(admission.final_action_stable_topology_sha256),
    )
    if (
        action_fence_sha256 != admission.claimed_action_fence_sha256
        or admission.operation_id != action_fence.operation_id
        or admission.approval_sha256 != action_fence.approval_sha256
        or admission.session_sha256 != action_fence.session_sha256
        or admission.claim_sha256 != action_fence.claim_sha256
        or admission.retained_claim_artifact_sha256 != action_fence.retained_claim_artifact_sha256
        or admission.final_action_observation_sha256 != action_fence.final_action_observation_sha256
        or admission.final_action_snapshot_sha256 != action_fence.final_action_snapshot_sha256
        or admission.final_action_stable_topology_sha256
        != action_fence.final_action_stable_topology_sha256
        or not _valid_active_controller_admission_capability(
            admission._capability,
            material,
            admission,
        )
    ):
        raise TrustedTimePostEnrollmentPersistentTopologyRejected(
            "trusted-time persistent active-controller admission is invalid"
        )
    return _payload_sha256(material), action_fence


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentPersistentContainerSnapshot:
    """Digest-only projection of one container in the fresh post-effect pass."""

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
            or _FULL_ID_PATTERN.fullmatch(self.container_id) is None
            or type(self.image_id) is not str
            or not self.image_id.startswith("sha256:")
            or _FULL_ID_PATTERN.fullmatch(self.image_id.removeprefix("sha256:")) is None
            or not _is_sha256(self.stable_inspection_projection_sha256)
            or not _is_sha256(self.running_state_projection_sha256)
            or not _is_sha256(self.image_configuration_projection_sha256)
        ):
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time persistent container snapshot is invalid"
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


def _same_container_as_staged(
    persistent: TrustedTimePostEnrollmentPersistentContainerSnapshot,
    staged: TrustedTimePostEnrollmentStagedContainerSnapshot,
) -> bool:
    return persistent.payload() == staged.payload()


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentPersistentTopologySnapshot:
    """Digest-only unqualified projection of one submitted post-release state."""

    operation_id: str
    approval_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    active_controller_admission_sha256: str
    final_action_snapshot_sha256: str
    final_action_stable_topology_sha256: str
    approved_launch: TrustedTimeImmutableLaunchEvidence
    created_topology_snapshot_sha256: str
    successor: TrustedTimePostEnrollmentStartSuccessor = field(repr=False)
    daemon_context_name: str
    daemon_endpoint: str
    daemon_id: str
    socket_volume_sha256: str
    state_volume_sha256: str
    network_id: str
    network_projection_sha256: str
    source: TrustedTimePostEnrollmentPersistentContainerSnapshot
    supervisor: TrustedTimePostEnrollmentPersistentContainerSnapshot
    database_secret_consumed_candidate_sha256: str
    release_marker_candidate_sha256: str
    release_staging_absence_candidate_sha256: str
    staged_input_retirement_candidate_sha256: str
    _admission: object = field(repr=False, compare=False)
    _final_action_staged_topology: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if (
                type(self._admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
                or type(self._final_action_staged_topology)
                is not TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot
                or type(self.approved_launch) is not TrustedTimeImmutableLaunchEvidence
                or type(self.successor) is not TrustedTimePostEnrollmentStartSuccessor
                or type(self.source) is not TrustedTimePostEnrollmentPersistentContainerSnapshot
                or type(self.supervisor) is not TrustedTimePostEnrollmentPersistentContainerSnapshot
            ):
                raise ValueError
            admission = self._admission
            final = self._final_action_staged_topology
            admission_sha256, action_fence = _validated_admission_sha256(admission)
            final.__post_init__()
            self.approved_launch.__post_init__()
            self.successor.__post_init__()
            self.source.__post_init__()
            self.supervisor.__post_init__()
            final_observation = cast(Any, action_fence._final_action_observation)
            claimed_fence = cast(Any, action_fence._claimed_fence)
            retained_claim = claimed_fence._handoff.retained_claim
            created_topology = claimed_fence._created_observation.snapshot
            if (
                final_observation.snapshot is not final
                or any(
                    not _is_sha256(value)
                    for value in (
                        self.approval_sha256,
                        self.claim_sha256,
                        self.retained_claim_artifact_sha256,
                        self.active_controller_admission_sha256,
                        self.final_action_snapshot_sha256,
                        self.final_action_stable_topology_sha256,
                        self.created_topology_snapshot_sha256,
                        self.socket_volume_sha256,
                        self.state_volume_sha256,
                        self.network_projection_sha256,
                        self.database_secret_consumed_candidate_sha256,
                        self.release_marker_candidate_sha256,
                        self.release_staging_absence_candidate_sha256,
                        self.staged_input_retirement_candidate_sha256,
                    )
                )
                or self.operation_id != admission.operation_id
                or self.approval_sha256 != admission.approval_sha256
                or self.claim_sha256 != admission.claim_sha256
                or self.retained_claim_artifact_sha256 != admission.retained_claim_artifact_sha256
                or self.active_controller_admission_sha256 != admission_sha256
                or self.final_action_snapshot_sha256 != final.snapshot_sha256
                or self.final_action_snapshot_sha256 != admission.final_action_snapshot_sha256
                or self.final_action_stable_topology_sha256 != final.stable_topology_sha256
                or self.final_action_stable_topology_sha256
                != admission.final_action_stable_topology_sha256
                or self.approved_launch != final.approved_launch
                or self.created_topology_snapshot_sha256 != final.created_topology_snapshot_sha256
                or self.created_topology_snapshot_sha256 != created_topology.snapshot_sha256
                or self.successor.predecessor_anchor_sha256
                != retained_claim.claim.reauthentication.current_anchor_sha256
                or self.daemon_context_name != final.daemon_context_name
                or self.daemon_endpoint != final.daemon_endpoint
                or self.daemon_id != final.daemon_id
                or self.socket_volume_sha256 != final.socket_volume_sha256
                or self.state_volume_sha256 != final.state_volume_sha256
                or type(self.network_id) is not str
                or _FULL_ID_PATTERN.fullmatch(self.network_id) is None
                or not _same_container_as_staged(self.source, final.source)
                or not _same_container_as_staged(self.supervisor, final.supervisor)
                or self.database_secret_consumed_candidate_sha256
                != final.database_secret_consumed_candidate_sha256
                or self.staged_input_retirement_candidate_sha256
                != final.staged_input_retirement_candidate_sha256
            ):
                raise ValueError
        except TrustedTimePostEnrollmentPersistentTopologyRejected:
            raise
        except BaseException:
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time persistent topology snapshot is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_payload()
        payload.update(
            {
                "active_controller_admission_sha256": (self.active_controller_admission_sha256),
                "approval_sha256": self.approval_sha256,
                "approved_launch": self.approved_launch.payload(),
                "claim_sha256": self.claim_sha256,
                "compose_project": POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
                "contract_version": POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION,
                "created_topology_snapshot_sha256": (self.created_topology_snapshot_sha256),
                "daemon_identity": {
                    "context_name": self.daemon_context_name,
                    "daemon_id": self.daemon_id,
                    "endpoint": self.daemon_endpoint,
                },
                "database_secret_consumed_candidate_sha256": (
                    self.database_secret_consumed_candidate_sha256
                ),
                "final_action_snapshot_sha256": self.final_action_snapshot_sha256,
                "final_action_stable_topology_sha256": (self.final_action_stable_topology_sha256),
                "network_id": self.network_id,
                "network_projection_sha256": self.network_projection_sha256,
                "operation_id": self.operation_id,
                "release_marker_candidate_sha256": self.release_marker_candidate_sha256,
                "release_staging_absence_candidate_sha256": (
                    self.release_staging_absence_candidate_sha256
                ),
                "retained_claim_artifact_sha256": (self.retained_claim_artifact_sha256),
                "service": POST_ENROLLMENT_START_SERVICE,
                "source_container": self.source.payload(),
                "staged_input_retirement_candidate_sha256": (
                    self.staged_input_retirement_candidate_sha256
                ),
                "status": self.status,
                "submitted_project_container_count": 2,
                "successor_candidate_sha256": _successor_sha256(self.successor),
                "supervisor_container": self.supervisor.payload(),
                "volume_identities": {
                    "socket_sha256": self.socket_volume_sha256,
                    "state_sha256": self.state_volume_sha256,
                },
            }
        )
        return payload

    @property
    def snapshot_sha256(self) -> str:
        return _payload_sha256(self.payload())

    active_controller_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    current_daemon_session_authenticated = property(_authority_is_never_granted)
    current_lock_session_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    inventory_authenticated = property(_authority_is_never_granted)
    network_identity_authenticated = property(_authority_is_never_granted)
    observation_provenance_authenticated = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    persistent_start_confirmed = property(_authority_is_never_granted)
    qualified = property(_authority_is_never_granted)
    release_absence_authenticated = property(_authority_is_never_granted)
    release_attempted = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    release_confirmed = property(_authority_is_never_granted)
    release_marker_authenticated = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    runtime_start_confirmed = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    sequence_2_confirmed = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authenticated = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    staged_input_retirement_authenticated = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    success_outcome_retained = property(_authority_is_never_granted)
    success_outcome_retention_authorized = property(_authority_is_never_granted)
    supervisor_start_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    topology_qualified = property(_authority_is_never_granted)
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


def _validated_network(
    candidate: object,
    *,
    expected_inventory: frozenset[str],
) -> tuple[str, str]:
    isolated, projection_sha256 = _isolated_json_projection(candidate, expected_type=dict)
    network = cast(dict[str, object], isolated)
    network_id = network.get("Id")
    labels = network.get("Labels")
    containers = network.get("Containers")
    config_from = network.get("ConfigFrom")
    if (
        set(network) != _NETWORK_KEYS
        or type(network_id) is not str
        or _FULL_ID_PATTERN.fullmatch(network_id) is None
        or network.get("Name") != COMPOSE_NETWORK_NAME
        or network.get("Driver") != "bridge"
        or network.get("Scope") != "local"
        or network.get("Internal") is not False
        or network.get("Attachable") is not False
        or network.get("Ingress") is not False
        or network.get("ConfigOnly") is not False
        or type(config_from) is not dict
        or config_from != {"Network": ""}
        or type(network.get("Created")) is not str
        or not network.get("Created")
        or network.get("EnableIPv6") is not False
        or type(network.get("IPAM")) is not dict
        or type(network.get("Options")) is not dict
        or type(labels) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in labels.items())
        or labels.get("com.docker.compose.project")
        != POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
        or labels.get("com.docker.compose.network") != "default"
        or type(containers) is not dict
        or frozenset(containers) != expected_inventory
    ):
        raise TrustedTimePostEnrollmentPersistentTopologyRejected(
            "trusted-time persistent network candidate is invalid"
        )
    for value in cast(dict[str, object], containers).values():
        if (
            type(value) is not dict
            or set(value) != _NETWORK_CONTAINER_KEYS
            or type(value.get("Name")) is not str
            or not value.get("Name")
            or type(value.get("EndpointID")) is not str
            or _FULL_ID_PATTERN.fullmatch(cast(str, value.get("EndpointID"))) is None
            or type(value.get("MacAddress")) is not str
            or _MAC_ADDRESS_PATTERN.fullmatch(cast(str, value.get("MacAddress"))) is None
            or type(value.get("IPv4Address")) is not str
            or type(value.get("IPv6Address")) is not str
            or value.get("IPv6Address") != ""
        ):
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time persistent network candidate is invalid"
            )
        try:
            ipv4 = ipaddress.ip_interface(cast(str, value["IPv4Address"]))
        except ValueError:
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time persistent network candidate is invalid"
            ) from None
        if ipv4.version != 4 or str(ipv4) != value["IPv4Address"]:
            raise TrustedTimePostEnrollmentPersistentTopologyRejected(
                "trusted-time persistent network candidate is invalid"
            )
    return network_id, projection_sha256


def validate_post_enrollment_start_persistent_topology(
    *,
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    final_action_staged_topology: TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    successor: TrustedTimePostEnrollmentStartSuccessor,
    approved_launch: TrustedTimeApprovedLaunch,
    daemon_identity_before: LocalDockerDaemonIdentity,
    daemon_identity_after: LocalDockerDaemonIdentity,
    volume_identities_before: TrustedTimeVolumeIdentities,
    volume_identities_after: TrustedTimeVolumeIdentities,
    project_container_ids_before: tuple[str, ...],
    project_container_ids_after: tuple[str, ...],
    project_network_before: dict[str, object],
    project_network_after: dict[str, object],
    container_inspections: dict[str, object],
    source_image_configuration: dict[str, object],
    supervisor_image_configuration: dict[str, object],
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
    database_secret_consumed_before: TrustedTimePostEnrollmentConsumedMarkerCandidate,
    database_secret_consumed_after: TrustedTimePostEnrollmentConsumedMarkerCandidate,
    release_marker_before: TrustedTimePostEnrollmentReleaseMarkerCandidate,
    release_marker_after: TrustedTimePostEnrollmentReleaseMarkerCandidate,
    release_staging_absences_before: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    release_staging_absences_after: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    staged_input_retirements_before: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
    staged_input_retirements_after: tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
) -> TrustedTimePostEnrollmentPersistentTopologySnapshot:
    """Bind candidates from one fresh post-effect pass without performing effects.

    ``final_action_staged_topology`` is only the exact pre-release baseline.  The
    remaining arguments are a distinct caller-supplied post-effect observation
    projection suitable for a later bounded reader's 16-read choreography.
    """

    try:
        if (
            type(admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
            or type(final_action_staged_topology)
            is not TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot
            or type(successor) is not TrustedTimePostEnrollmentStartSuccessor
            or type(approved_launch) is not TrustedTimeApprovedLaunch
            or type(database_secret_consumed_before)
            is not TrustedTimePostEnrollmentConsumedMarkerCandidate
            or type(database_secret_consumed_after)
            is not TrustedTimePostEnrollmentConsumedMarkerCandidate
            or type(release_marker_before) is not TrustedTimePostEnrollmentReleaseMarkerCandidate
            or type(release_marker_after) is not TrustedTimePostEnrollmentReleaseMarkerCandidate
        ):
            raise ValueError
        admission_sha256, action_fence = _validated_admission_sha256(admission)
        final_action_staged_topology.__post_init__()
        successor.__post_init__()
        approved_launch.__post_init__()
        database_secret_consumed_before.__post_init__()
        database_secret_consumed_after.__post_init__()
        release_marker_before.__post_init__()
        release_marker_after.__post_init__()

        final_observation = cast(Any, action_fence._final_action_observation)
        claimed_fence = cast(Any, action_fence._claimed_fence)
        approval = claimed_fence._approval
        retained_claim = claimed_fence._handoff.retained_claim
        created_topology = claimed_fence._created_observation.snapshot
        proposed_launch = approval.proposed_launch
        if (
            final_observation.snapshot is not final_action_staged_topology
            or final_action_staged_topology.operation_id != admission.operation_id
            or final_action_staged_topology.approval_sha256 != admission.approval_sha256
            or final_action_staged_topology.snapshot_sha256
            != admission.final_action_snapshot_sha256
            or final_action_staged_topology.stable_topology_sha256
            != admission.final_action_stable_topology_sha256
            or retained_claim.claim.claim_sha256 != admission.claim_sha256
            or retained_claim.artifact_sha256 != admission.retained_claim_artifact_sha256
            or successor.predecessor_anchor_sha256
            != retained_claim.claim.reauthentication.current_anchor_sha256
            or proposed_launch.git_revision != approved_launch.git_revision
            or proposed_launch.image_admission_sha256 != approved_launch.image_admission_sha256
            or proposed_launch.source_image_id != approved_launch.source_image_id
            or proposed_launch.supervisor_image_id != approved_launch.supervisor_image_id
            or final_action_staged_topology.approved_launch != proposed_launch
            or not _valid_daemon_identity(daemon_identity_before)
            or not _valid_daemon_identity(daemon_identity_after)
            or daemon_identity_before != daemon_identity_after
            or final_action_staged_topology.daemon_context_name
            != daemon_identity_before.context_name
            or final_action_staged_topology.daemon_endpoint != daemon_identity_before.endpoint
            or final_action_staged_topology.daemon_id != daemon_identity_before.daemon_id
            or type(volume_identities_before) is not TrustedTimeVolumeIdentities
            or type(volume_identities_after) is not TrustedTimeVolumeIdentities
        ):
            raise ValueError
        volume_identities_before.__post_init__()
        volume_identities_after.__post_init__()
        if (
            volume_identities_before != volume_identities_after
            or final_action_staged_topology.socket_volume_sha256
            != volume_identities_before.socket_sha256
            or final_action_staged_topology.state_volume_sha256
            != volume_identities_before.state_sha256
        ):
            raise ValueError

        inventory_before = _validated_container_inventory(project_container_ids_before)
        inventory_after = _validated_container_inventory(project_container_ids_after)
        expected_inventory = frozenset(
            {
                final_action_staged_topology.source.container_id,
                final_action_staged_topology.supervisor.container_id,
            }
        )
        if (
            inventory_before != inventory_after
            or inventory_before != expected_inventory
            or type(container_inspections) is not dict
            or len(container_inspections) != 2
            or any(type(container_id) is not str for container_id in container_inspections)
            or set(container_inspections) != set(expected_inventory)
        ):
            raise ValueError

        network_id_before, network_sha256_before = _validated_network(
            project_network_before,
            expected_inventory=expected_inventory,
        )
        network_id_after, network_sha256_after = _validated_network(
            project_network_after,
            expected_inventory=expected_inventory,
        )
        if network_id_before != network_id_after or network_sha256_before != network_sha256_after:
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
        _, staged_retirement_sha256 = _validated_absence_candidates(
            staged_input_retirements_before,
            staged_input_retirements_after,
            expected_paths=frozenset(os.fspath(path) for path in staged_paths),
            label="staged-input retirement",
        )
        _, release_staging_absence_sha256 = _validated_absence_candidates(
            release_staging_absences_before,
            release_staging_absences_after,
            expected_paths=frozenset({POST_ENROLLMENT_START_RELEASE_STAGING_PATH}),
            label="release-staging absence",
        )
        if (
            staged_retirement_sha256
            != final_action_staged_topology.staged_input_retirement_candidate_sha256
            or database_secret_consumed_before != database_secret_consumed_after
            or database_secret_consumed_before.candidate_sha256
            != final_action_staged_topology.database_secret_consumed_candidate_sha256
            or release_marker_before != release_marker_after
        ):
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
            source_id != final_action_staged_topology.source.container_id
            or supervisor_id != final_action_staged_topology.supervisor.container_id
            or source_configuration_sha256
            != final_action_staged_topology.source.image_configuration_projection_sha256
            or supervisor_configuration_sha256
            != final_action_staged_topology.supervisor.image_configuration_projection_sha256
        ):
            raise ValueError

        validate_exact_staged_running_container(
            source_inspection,
            expected_container_id=source_id,
            expected_image_id=approved_launch.source_image_id,
            expected_image_configuration=source_configuration,
            expected_service=_SOURCE_SERVICE,
        )
        validate_exact_staged_running_container(
            supervisor_inspection,
            expected_container_id=supervisor_id,
            expected_image_id=approved_launch.supervisor_image_id,
            expected_image_configuration=supervisor_configuration,
            expected_service=_SUPERVISOR_SERVICE,
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
        source = TrustedTimePostEnrollmentPersistentContainerSnapshot(
            service=_SOURCE_SERVICE,
            container_id=source_id,
            image_id=approved_launch.source_image_id,
            stable_inspection_projection_sha256=source_projection_sha256,
            running_state_projection_sha256=source_state_sha256,
            image_configuration_projection_sha256=source_configuration_sha256,
        )
        supervisor = TrustedTimePostEnrollmentPersistentContainerSnapshot(
            service=_SUPERVISOR_SERVICE,
            container_id=supervisor_id,
            image_id=approved_launch.supervisor_image_id,
            stable_inspection_projection_sha256=supervisor_projection_sha256,
            running_state_projection_sha256=supervisor_state_sha256,
            image_configuration_projection_sha256=supervisor_configuration_sha256,
        )
        if not _same_container_as_staged(
            source,
            final_action_staged_topology.source,
        ) or not _same_container_as_staged(
            supervisor,
            final_action_staged_topology.supervisor,
        ):
            raise ValueError

        return TrustedTimePostEnrollmentPersistentTopologySnapshot(
            operation_id=admission.operation_id,
            approval_sha256=admission.approval_sha256,
            claim_sha256=admission.claim_sha256,
            retained_claim_artifact_sha256=admission.retained_claim_artifact_sha256,
            active_controller_admission_sha256=admission_sha256,
            final_action_snapshot_sha256=final_action_staged_topology.snapshot_sha256,
            final_action_stable_topology_sha256=(
                final_action_staged_topology.stable_topology_sha256
            ),
            approved_launch=proposed_launch,
            created_topology_snapshot_sha256=created_topology.snapshot_sha256,
            successor=successor,
            daemon_context_name=daemon_identity_before.context_name,
            daemon_endpoint=daemon_identity_before.endpoint,
            daemon_id=daemon_identity_before.daemon_id,
            socket_volume_sha256=volume_identities_before.socket_sha256,
            state_volume_sha256=volume_identities_before.state_sha256,
            network_id=network_id_before,
            network_projection_sha256=network_sha256_before,
            source=source,
            supervisor=supervisor,
            database_secret_consumed_candidate_sha256=(
                database_secret_consumed_before.candidate_sha256
            ),
            release_marker_candidate_sha256=release_marker_before.candidate_sha256,
            release_staging_absence_candidate_sha256=release_staging_absence_sha256,
            staged_input_retirement_candidate_sha256=staged_retirement_sha256,
            _admission=admission,
            _final_action_staged_topology=final_action_staged_topology,
        )
    except TrustedTimePostEnrollmentPersistentTopologyRejected:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentPersistentTopologyRejected(
            "trusted-time persistent topology snapshot was rejected"
        ) from None


__all__ = [
    "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION",
    "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS",
    "TrustedTimePostEnrollmentPersistentContainerSnapshot",
    "TrustedTimePostEnrollmentPersistentTopologyRejected",
    "TrustedTimePostEnrollmentPersistentTopologySnapshot",
    "TrustedTimePostEnrollmentReleaseMarkerCandidate",
    "validate_post_enrollment_start_persistent_topology",
]
