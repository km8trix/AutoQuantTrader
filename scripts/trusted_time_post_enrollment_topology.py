"""Pure, dormant binding for one caller-supplied created-topology candidate.

This module performs no I/O, reads no clock, starts no process, retains no
claim, and grants no authority.  It validates already-supplied Docker
inspection projections and retains only nonsecret identities and digests.  A
future active reader, not this pure module, must reject duplicate keys while
parsing bounded raw Docker bytes and establish the observations' provenance.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlsplit

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
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
    TrustedTimeVolumeIdentities,
    validate_exact_never_started_created_container,
)

POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-created-topology-snapshot-v1"
)
POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS = "created_topology_snapshot_unqualified"
POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT = "autoquanttrader-trusted-time"

_SOURCE_SERVICE = "chrony-nts"
_SUPERVISOR_SERVICE = "trusted-time-supervisor"
_SERVICES = frozenset({_SOURCE_SERVICE, _SUPERVISOR_SERVICE})
_MAXIMUM_JSON_PROJECTION_BYTES = 4 * 1_024 * 1_024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_CONTEXT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}")
_DAEMON_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,255}")
_MAXIMUM_JSON_PROJECTION_NODES = 131_072
_MAXIMUM_JSON_INTEGER_BITS = 256


def _authority_is_never_granted(_: object) -> bool:
    return False


class TrustedTimePostEnrollmentCreatedTopologyRejected(ValueError):
    """The submitted created-topology snapshot could not be bound."""


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _require_exact_json_tree(
    value: object,
    *,
    depth: int = 0,
    remaining_nodes: list[int],
    remaining_ascii_bytes: list[int],
) -> None:
    """Reject lossy values and exhaust a pre-serialization size budget."""

    def consume(maximum_ascii_bytes: int) -> None:
        remaining_ascii_bytes[0] -= maximum_ascii_bytes
        if remaining_ascii_bytes[0] < 0:
            raise ValueError

    def require(current: object, *, current_depth: int, node_already_counted: bool) -> None:
        if current_depth > 64 or remaining_nodes[0] < 0:
            raise ValueError
        if not node_already_counted:
            remaining_nodes[0] -= 1
            if remaining_nodes[0] < 0:
                raise ValueError
        if current is None:
            consume(4)
            return
        if type(current) is bool:
            consume(5)
            return
        if type(current) is int:
            integer_bits = current.bit_length()
            if integer_bits > _MAXIMUM_JSON_INTEGER_BITS:
                raise ValueError
            # A signed base-10 rendering cannot exceed one digit per binary bit,
            # plus a possible sign and one zero digit.
            consume(max(1, integer_bits) + 2)
            return
        if type(current) is str:
            # ``ensure_ascii`` can render one non-BMP code point as two six-byte
            # surrogate escapes.  Quotes are included in the conservative bound.
            consume(2 + 12 * len(current))
            return
        if type(current) is float:
            if not math.isfinite(current):
                raise ValueError
            consume(32)
            return
        if type(current) is list:
            consume(2 + max(0, len(current) - 1))
            for item in current:
                require(
                    item,
                    current_depth=current_depth + 1,
                    node_already_counted=False,
                )
            return
        if type(current) is dict:
            child_node_count = 2 * len(current)
            if child_node_count > remaining_nodes[0]:
                raise ValueError
            remaining_nodes[0] -= child_node_count
            consume(2 + max(0, child_node_count - 1))
            if any(type(key) is not str for key in current):
                raise ValueError
            for key, item in current.items():
                require(
                    key,
                    current_depth=current_depth + 1,
                    node_already_counted=True,
                )
                require(
                    item,
                    current_depth=current_depth + 1,
                    node_already_counted=True,
                )
            return
        raise ValueError

    require(value, current_depth=depth, node_already_counted=False)


def _isolated_json_projection(
    value: object,
    *,
    expected_type: type[object],
) -> tuple[object, str]:
    """Return one bounded JSON-only copy and its exact canonical digest."""

    if type(value) is not expected_type:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created-topology projection is invalid"
        )
    try:
        _require_exact_json_tree(
            value,
            remaining_nodes=[_MAXIMUM_JSON_PROJECTION_NODES],
            remaining_ascii_bytes=[_MAXIMUM_JSON_PROJECTION_BYTES],
        )
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii", errors="strict")
        if not encoded or len(encoded) > _MAXIMUM_JSON_PROJECTION_BYTES:
            raise ValueError
        isolated: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        repeated = json.dumps(
            isolated,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii", errors="strict")
    except (
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created-topology projection is invalid"
        ) from None
    if type(isolated) is not expected_type or repeated != encoded:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created-topology projection is invalid"
        )
    return isolated, hashlib.sha256(encoded).hexdigest()


def _valid_daemon_identity(identity: object) -> bool:
    if (
        type(identity) is not LocalDockerDaemonIdentity
        or type(identity.context_name) is not str
        or (
            identity.context_name != "<DOCKER_HOST>"
            and _CONTEXT_NAME_PATTERN.fullmatch(identity.context_name) is None
        )
        or type(identity.endpoint) is not str
        or not identity.endpoint
        or len(identity.endpoint) > 4_096
        or any(ord(character) < 32 or ord(character) == 127 for character in identity.endpoint)
        or type(identity.daemon_id) is not str
        or _DAEMON_ID_PATTERN.fullmatch(identity.daemon_id) is None
    ):
        return False
    try:
        parsed = urlsplit(identity.endpoint)
        decoded_path = unquote(parsed.path)
        socket_path = Path(decoded_path)
        canonical_socket_path = Path(os.path.abspath(socket_path))
    except (OSError, TypeError, ValueError):
        return False
    return (
        parsed.scheme == "unix"
        and not parsed.netloc
        and not parsed.query
        and not parsed.fragment
        and decoded_path == parsed.path
        and decoded_path.startswith("/")
        and not decoded_path.startswith("//")
        and socket_path.is_absolute()
        and socket_path == canonical_socket_path
        and not any(component in {".", ".."} for component in socket_path.parts)
        and str(socket_path) == decoded_path
        and identity.endpoint == f"unix://{decoded_path}"
    )


def _validated_container_inventory(value: object) -> frozenset[str]:
    if (
        type(value) is not tuple
        or len(value) != 2
        or any(
            type(container_id) is not str or _CONTAINER_ID_PATTERN.fullmatch(container_id) is None
            for container_id in value
        )
        or len(set(value)) != 2
    ):
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created-topology inventory is invalid"
        )
    return frozenset(cast(tuple[str, str], value))


def _inspection_container(inspection: object) -> dict[str, object]:
    if type(inspection) is not list or len(inspection) != 1 or type(inspection[0]) is not dict:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created container inspection is invalid"
        )
    return cast(dict[str, object], inspection[0])


def _inspection_role(
    container_id: str,
    inspection: object,
) -> str:
    container = _inspection_container(inspection)
    configuration = container.get("Config")
    if type(configuration) is not dict:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created container role is invalid"
        )
    labels = configuration.get("Labels")
    if type(labels) is not dict:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created container role is invalid"
        )
    service = labels.get("com.docker.compose.service")
    if (
        container.get("Id") != container_id
        or labels.get("com.docker.compose.project")
        != POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
        or service not in _SERVICES
    ):
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created container role is invalid"
        )
    return cast(str, service)


def _start_argv(container_id: str) -> tuple[str, ...]:
    if type(container_id) is not str or _CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created container start projection is invalid"
        )
    return ("docker", "container", "start", container_id)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentCreatedContainerSnapshot:
    """Digest-only projection of one submitted never-started candidate."""

    service: str
    container_id: str
    image_id: str
    inspection_projection_sha256: str
    image_configuration_projection_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.service) is not str
            or self.service not in _SERVICES
            or type(self.container_id) is not str
            or _CONTAINER_ID_PATTERN.fullmatch(self.container_id) is None
            or type(self.image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.image_id) is None
            or type(self.inspection_projection_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.inspection_projection_sha256) is None
            or type(self.image_configuration_projection_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.image_configuration_projection_sha256) is None
        ):
            raise TrustedTimePostEnrollmentCreatedTopologyRejected(
                "trusted-time created container snapshot is invalid"
            )

    def payload(self) -> dict[str, str]:
        return {
            "container_id": self.container_id,
            "image_configuration_projection_sha256": (self.image_configuration_projection_sha256),
            "image_id": self.image_id,
            "inspection_projection_sha256": self.inspection_projection_sha256,
            "service": self.service,
        }


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentCreatedTopologySnapshot:
    """Non-authorizing projection over two caller-supplied candidates."""

    operation_id: str
    approval_sha256: str
    review_projection_sha256: str
    confirmed_enrollment_evidence_sha256: str
    approved_launch: TrustedTimeImmutableLaunchEvidence
    daemon_context_name: str
    daemon_endpoint: str
    daemon_id: str
    socket_volume_sha256: str
    state_volume_sha256: str
    source: TrustedTimePostEnrollmentCreatedContainerSnapshot
    supervisor: TrustedTimePostEnrollmentCreatedContainerSnapshot
    source_start_argv: tuple[str, ...]
    supervisor_start_argv: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            if type(self.approved_launch) is not TrustedTimeImmutableLaunchEvidence:
                raise ValueError
            self.approved_launch.__post_init__()
            daemon_identity = LocalDockerDaemonIdentity(
                context_name=self.daemon_context_name,
                endpoint=self.daemon_endpoint,
                daemon_id=self.daemon_id,
            )
            if (
                not _is_uuid4(self.operation_id)
                or type(self.approval_sha256) is not str
                or _SHA256_PATTERN.fullmatch(self.approval_sha256) is None
                or type(self.review_projection_sha256) is not str
                or _SHA256_PATTERN.fullmatch(self.review_projection_sha256) is None
                or type(self.confirmed_enrollment_evidence_sha256) is not str
                or _SHA256_PATTERN.fullmatch(self.confirmed_enrollment_evidence_sha256) is None
                or not _valid_daemon_identity(daemon_identity)
                or type(self.socket_volume_sha256) is not str
                or _SHA256_PATTERN.fullmatch(self.socket_volume_sha256) is None
                or type(self.state_volume_sha256) is not str
                or _SHA256_PATTERN.fullmatch(self.state_volume_sha256) is None
                or type(self.source) is not TrustedTimePostEnrollmentCreatedContainerSnapshot
                or type(self.supervisor) is not TrustedTimePostEnrollmentCreatedContainerSnapshot
                or self.source.service != _SOURCE_SERVICE
                or self.supervisor.service != _SUPERVISOR_SERVICE
                or self.source.container_id == self.supervisor.container_id
                or self.source.image_id != self.approved_launch.source_image_id
                or self.supervisor.image_id != self.approved_launch.supervisor_image_id
                or type(self.source_start_argv) is not tuple
                or self.source_start_argv != _start_argv(self.source.container_id)
                or type(self.supervisor_start_argv) is not tuple
                or self.supervisor_start_argv != _start_argv(self.supervisor.container_id)
            ):
                raise ValueError
            self.source.__post_init__()
            self.supervisor.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentCreatedTopologyRejected(
                "trusted-time created topology snapshot is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        }
        payload.update(
            {
                "approval_sha256": self.approval_sha256,
                "approved_launch": self.approved_launch.payload(),
                "authority_granted": False,
                "claim_retention_authorized": False,
                "compose_project": POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
                "confirmed_enrollment_evidence_sha256": (self.confirmed_enrollment_evidence_sha256),
                "container_identity_authenticated": False,
                "contract_version": (POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION),
                "daemon_identity": {
                    "context_name": self.daemon_context_name,
                    "daemon_id": self.daemon_id,
                    "endpoint": self.daemon_endpoint,
                },
                "daemon_identity_authenticated": False,
                "database_secret_disclosed": False,
                "inventory_authenticated": False,
                "operation_id": self.operation_id,
                "persistent_start_authorized": False,
                "release_authorized": False,
                "review_projection_sha256": self.review_projection_sha256,
                "sequence_2_authorized": False,
                "service": POST_ENROLLMENT_START_SERVICE,
                "shutdown_authorized": False,
                "source_container": self.source.payload(),
                "source_start_authorized": False,
                "start_order_argv": [
                    list(self.source_start_argv),
                    list(self.supervisor_start_argv),
                ],
                "status": self.status,
                "submitted_project_container_count": 2,
                "supervisor_container": self.supervisor.payload(),
                "supervisor_start_authorized": False,
                "topology_authenticated": False,
                "topology_mutation_authorized": False,
                "volume_identities": {
                    "socket_sha256": self.socket_volume_sha256,
                    "state_sha256": self.state_volume_sha256,
                },
                "volume_identity_authenticated": False,
            }
        )
        return payload

    @property
    def snapshot_sha256(self) -> str:
        return hashlib.sha256(canonical_first_enrollment_json_bytes(self.payload())).hexdigest()

    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    inventory_authenticated = property(_authority_is_never_granted)
    observation_provenance_authenticated = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    source_start_authenticated = property(_authority_is_never_granted)
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


def validate_post_enrollment_start_created_topology(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    approved_launch: TrustedTimeApprovedLaunch,
    daemon_identity_before: LocalDockerDaemonIdentity,
    daemon_identity_after: LocalDockerDaemonIdentity,
    volume_identities_before: TrustedTimeVolumeIdentities,
    volume_identities_after: TrustedTimeVolumeIdentities,
    project_container_ids_before: tuple[str, ...],
    project_container_ids_after: tuple[str, ...],
    container_inspections: dict[str, object],
    source_image_configuration: dict[str, object],
    supervisor_image_configuration: dict[str, object],
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
) -> TrustedTimePostEnrollmentCreatedTopologySnapshot:
    """Bind a caller-supplied candidate projection without executing an action."""

    try:
        if (
            type(approval) is not TrustedTimePostEnrollmentStartApproval
            or type(approved_launch) is not TrustedTimeApprovedLaunch
        ):
            raise ValueError
        approval.__post_init__()
        approved_launch.__post_init__()
        proposed_launch = approval.proposed_launch
        if (
            proposed_launch.git_revision != approved_launch.git_revision
            or proposed_launch.image_admission_sha256 != approved_launch.image_admission_sha256
            or proposed_launch.source_image_id != approved_launch.source_image_id
            or proposed_launch.supervisor_image_id != approved_launch.supervisor_image_id
            or not _valid_daemon_identity(daemon_identity_before)
            or not _valid_daemon_identity(daemon_identity_after)
            or daemon_identity_after != daemon_identity_before
            or type(volume_identities_before) is not TrustedTimeVolumeIdentities
            or type(volume_identities_after) is not TrustedTimeVolumeIdentities
        ):
            raise ValueError
        volume_identities_before.__post_init__()
        volume_identities_after.__post_init__()
        if volume_identities_after != volume_identities_before:
            raise ValueError

        inventory_before = _validated_container_inventory(project_container_ids_before)
        inventory_after = _validated_container_inventory(project_container_ids_after)
        if (
            inventory_after != inventory_before
            or type(container_inspections) is not dict
            or len(container_inspections) != 2
            or any(type(container_id) is not str for container_id in container_inspections)
            or any(
                _CONTAINER_ID_PATTERN.fullmatch(container_id) is None
                for container_id in container_inspections
            )
        ):
            raise ValueError
        if set(container_inspections) != set(inventory_before):
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

        roles: dict[str, tuple[str, object, str]] = {}
        for container_id, submitted_inspection in container_inspections.items():
            isolated_inspection, inspection_sha256 = _isolated_json_projection(
                submitted_inspection,
                expected_type=list,
            )
            service = _inspection_role(container_id, isolated_inspection)
            if service in roles:
                raise ValueError
            roles[service] = (
                container_id,
                isolated_inspection,
                inspection_sha256,
            )
        if set(roles) != _SERVICES:
            raise ValueError

        source_id, source_inspection, source_inspection_sha256 = roles[_SOURCE_SERVICE]
        supervisor_id, supervisor_inspection, supervisor_inspection_sha256 = roles[
            _SUPERVISOR_SERVICE
        ]
        validate_exact_never_started_created_container(
            source_inspection,
            expected_container_id=source_id,
            expected_image_id=approved_launch.source_image_id,
            expected_image_configuration=source_configuration,
            expected_service=_SOURCE_SERVICE,
        )
        validate_exact_never_started_created_container(
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

        return TrustedTimePostEnrollmentCreatedTopologySnapshot(
            operation_id=approval.operation_id,
            approval_sha256=approval.approval_sha256,
            review_projection_sha256=approval.review.projection_sha256,
            confirmed_enrollment_evidence_sha256=(approval.confirmed_enrollment.evidence_sha256),
            approved_launch=proposed_launch,
            daemon_context_name=daemon_identity_before.context_name,
            daemon_endpoint=daemon_identity_before.endpoint,
            daemon_id=daemon_identity_before.daemon_id,
            socket_volume_sha256=volume_identities_before.socket_sha256,
            state_volume_sha256=volume_identities_before.state_sha256,
            source=TrustedTimePostEnrollmentCreatedContainerSnapshot(
                service=_SOURCE_SERVICE,
                container_id=source_id,
                image_id=approved_launch.source_image_id,
                inspection_projection_sha256=source_inspection_sha256,
                image_configuration_projection_sha256=(source_configuration_sha256),
            ),
            supervisor=TrustedTimePostEnrollmentCreatedContainerSnapshot(
                service=_SUPERVISOR_SERVICE,
                container_id=supervisor_id,
                image_id=approved_launch.supervisor_image_id,
                inspection_projection_sha256=supervisor_inspection_sha256,
                image_configuration_projection_sha256=(supervisor_configuration_sha256),
            ),
            source_start_argv=_start_argv(source_id),
            supervisor_start_argv=_start_argv(supervisor_id),
        )
    except TrustedTimePostEnrollmentCreatedTopologyRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentCreatedTopologyRejected(
            "trusted-time created topology snapshot was rejected"
        ) from None


__all__ = [
    "POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION",
    "POST_ENROLLMENT_CREATED_TOPOLOGY_STATUS",
    "TrustedTimePostEnrollmentCreatedContainerSnapshot",
    "TrustedTimePostEnrollmentCreatedTopologyRejected",
    "TrustedTimePostEnrollmentCreatedTopologySnapshot",
    "validate_post_enrollment_start_created_topology",
]
