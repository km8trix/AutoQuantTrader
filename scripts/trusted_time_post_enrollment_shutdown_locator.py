"""Pure durable locator for a later post-enrollment graceful stop.

The locator preserves the complete nonsecret persistent-topology projection
needed by a later process.  It performs no I/O, reads no clock, mutates no
runtime, and grants no shutdown or operational authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Never, cast
from urllib.parse import unquote, urlsplit

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import POST_ENROLLMENT_START_SERVICE
from scripts.start_trusted_time_supervisor import (
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
)
from scripts.trusted_time_post_enrollment_persistent_topology import (
    _CLOSED_FIELDS as _PERSISTENT_TOPOLOGY_CLOSED_FIELDS,
)
from scripts.trusted_time_post_enrollment_persistent_topology import (
    POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION,
    POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS,
    TrustedTimePostEnrollmentPersistentTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT,
    post_enrollment_created_topology_network_name,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    _finalize_post_enrollment_shutdown_locator_projection_type,
    _stage_post_enrollment_shutdown_locator_type,
)

POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-durable-shutdown-locator-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_SERVICE = POST_ENROLLMENT_START_SERVICE
POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS = "durable_shutdown_locator_unqualified"
POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES = 64 * 1_024

_MAXIMUM_PERSISTENT_TOPOLOGY_BYTES = 64 * 1_024
_MAXIMUM_JSON_DEPTH = 16
_MAXIMUM_JSON_NODES = 1_024
_MAXIMUM_JSON_INTEGER_BITS = 256
_SOURCE_SERVICE = "chrony-nts"
_SUPERVISOR_SERVICE = "trusted-time-supervisor"
_CONTEXT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}")
_DAEMON_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,255}")

_CLOSED_FIELDS = (
    "active_controller_authorized",
    "authority_granted",
    "claim_retention_authorized",
    "clean_stop_authorized",
    "container_removal_authorized",
    "controller_execution_authorized",
    "database_secret_disclosed",
    "execution_admission_authorized",
    "execution_attempt_reservation_authorized",
    "network_removal_authorized",
    "outcome_retention_authorized",
    "persistent_start_authorized",
    "qualified",
    "release_authorized",
    "retry_authorized",
    "runtime_start_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
    "source_stop_authorized",
    "source_start_authorized",
    "success_outcome_retention_authorized",
    "supervisor_signal_authorized",
    "supervisor_stop_authorized",
    "supervisor_start_authorized",
    "teardown_authorized",
    "topology_mutation_authorized",
    "volume_removal_authorized",
)

_FIELDS = (
    "active_controller_session_sha256",
    "contract_version",
    "network_name",
    "persistent_topology",
    "persistent_topology_sha256",
    "persistent_topology_transcript_sha256",
    "service",
    "socket_volume_name",
    "state_volume_name",
    "status",
)

_PERSISTENT_TOPOLOGY_FIELDS = (
    "active_controller_admission_sha256",
    "approval_sha256",
    "approved_launch",
    "claim_sha256",
    "compose_project",
    "contract_version",
    "created_topology_snapshot_sha256",
    "daemon_identity",
    "database_secret_consumed_candidate_sha256",
    "final_action_snapshot_sha256",
    "final_action_stable_topology_sha256",
    "network_id",
    "network_projection_sha256",
    "operation_id",
    "release_marker_candidate_sha256",
    "release_staging_absence_candidate_sha256",
    "retained_claim_artifact_sha256",
    "service",
    "source_container",
    "staged_input_retirement_candidate_sha256",
    "status",
    "submitted_project_container_count",
    "successor_candidate_sha256",
    "supervisor_container",
    "volume_identities",
)

_CONTAINER_FIELDS = frozenset(
    {
        "container_id",
        "image_configuration_projection_sha256",
        "image_id",
        "running_state_projection_sha256",
        "service",
        "stable_inspection_projection_sha256",
    }
)


class TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected(ValueError):
    """The submitted durable shutdown locator is invalid."""


class _InvalidLocator(ValueError):
    pass


type _CanonicalJsonObject = tuple[
    str,
    tuple[tuple[str, object], ...],
]
type _PersistentContainerProjection = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
]
type _PersistentTopologyProjection = tuple[
    str,
    _CanonicalJsonObject,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
]
type _ShutdownLocatorProjection = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    bytes,
    tuple[str, ...],
]


def _tagged_tuple_slot(
    value: object,
    *,
    tag: str,
    length: int,
    index: int,
) -> object:
    if (
        type(tag) is not str
        or type(length) is not int
        or type(index) is not int
        or index < 1
        or index >= length
        or type(value) is not tuple
        or len(value) != length
        or tuple.__getitem__(value, 0) != tag
    ):
        _invalid()
    return tuple.__getitem__(value, index)


def _canonical_json_object_items(value: object) -> tuple[tuple[str, object], ...]:
    items = _tagged_tuple_slot(
        value,
        tag="trusted-time-canonical-json-object-v1",
        length=2,
        index=1,
    )
    if type(items) is not tuple:
        _invalid()
    for entry in items:
        if (
            type(entry) is not tuple
            or len(entry) != 2
            or type(tuple.__getitem__(entry, 0)) is not str
        ):
            _invalid()
    return cast(tuple[tuple[str, object], ...], items)


def _new_canonical_json_object(
    items: tuple[tuple[str, object], ...],
) -> _CanonicalJsonObject:
    return ("trusted-time-canonical-json-object-v1", items)


def _persistent_container_slot(
    value: _PersistentContainerProjection,
    index: int,
) -> object:
    return _tagged_tuple_slot(
        value,
        tag="trusted-time-persistent-container-projection-v1",
        length=7,
        index=index,
    )


def _persistent_topology_slot(
    value: _PersistentTopologyProjection,
    index: int,
) -> object:
    return _tagged_tuple_slot(
        value,
        tag="trusted-time-persistent-topology-projection-v1",
        length=12,
        index=index,
    )


def _shutdown_locator_slot(
    value: _ShutdownLocatorProjection,
    index: int,
) -> object:
    return _tagged_tuple_slot(
        value,
        tag="trusted-time-shutdown-locator-projection-v1",
        length=9,
        index=index,
    )


def _invalid() -> Never:
    raise _InvalidLocator


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_git_revision(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_image_id(value: object) -> bool:
    return type(value) is str and value.startswith("sha256:") and _is_sha256(value[7:])


def _is_container_id(value: object) -> bool:
    return _is_sha256(value)


def _valid_daemon_identity_values(
    context_name: object,
    endpoint: object,
    daemon_id: object,
) -> bool:
    if (
        type(context_name) is not str
        or (
            context_name != "<DOCKER_HOST>"
            and _CONTEXT_NAME_PATTERN.fullmatch(context_name) is None
        )
        or type(endpoint) is not str
        or not endpoint
        or len(endpoint) > 4_096
        or any(ord(character) < 32 or ord(character) == 127 for character in endpoint)
        or type(daemon_id) is not str
        or _DAEMON_ID_PATTERN.fullmatch(daemon_id) is None
    ):
        return False
    try:
        parsed = urlsplit(endpoint)
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
        and endpoint == f"unix://{decoded_path}"
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> _CanonicalJsonObject:
    if type(pairs) is not list:
        _invalid()
    names: set[str] = set()
    immutable: list[tuple[str, object]] = []
    for entry in pairs:
        if type(entry) is not tuple or len(entry) != 2:
            _invalid()
        key = tuple.__getitem__(entry, 0)
        value = tuple.__getitem__(entry, 1)
        if type(key) is not str or key in names:
            _invalid()
        names.add(key)
        immutable.append((key, value))
    return _new_canonical_json_object(tuple(immutable))


def _bounded_json_integer(token: str) -> int:
    if len(token) > 80:
        _invalid()
    value = int(token)
    if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
        _invalid()
    return value


def _require_bounded_json_tree(root: object) -> None:
    def _node_count(value: object, depth: int) -> int:
        if depth > _MAXIMUM_JSON_DEPTH:
            _invalid()
        if value is None or type(value) is bool:
            return 1
        if type(value) is str:
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
                _invalid()
            return 1
        if type(value) is int:
            if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
                _invalid()
            return 1
        if (
            type(value) is tuple
            and len(value) == 2
            and tuple.__getitem__(value, 0) == ("trusted-time-canonical-json-object-v1")
        ):
            items = _canonical_json_object_items(value)
            keys = tuple(key for key, _ in items)
            if len(keys) != len(frozenset(keys)):
                _invalid()
            child_counts = tuple(
                _node_count(key, depth + 1) + _node_count(item, depth + 1) for key, item in items
            )
            total = 1 + sum(child_counts)
            if total > _MAXIMUM_JSON_NODES:
                _invalid()
            return total
        _invalid()

    if _node_count(root, 0) > _MAXIMUM_JSON_NODES:
        _invalid()


def _canonical_json_value_bytes(value: object) -> bytes:
    if (
        type(value) is tuple
        and len(value) == 2
        and tuple.__getitem__(value, 0) == ("trusted-time-canonical-json-object-v1")
    ):
        items = _canonical_json_object_items(value)
        keys = tuple(key for key, _ in items)
        if len(keys) != len(frozenset(keys)):
            _invalid()
        ordered = tuple(sorted(items, key=lambda entry: cast(str, tuple.__getitem__(entry, 0))))
        parts = tuple(
            json.dumps(
                key,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii", errors="strict")
            + b":"
            + _canonical_json_value_bytes(item)
            for key, item in ordered
        )
        return b"{" + b",".join(parts) + b"}"
    if value is None or type(value) in {bool, int, str}:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii", errors="strict")
    _invalid()


def _canonical_json_object_bytes(value: object) -> bytes:
    _canonical_json_object_items(value)
    return _canonical_json_value_bytes(value) + b"\n"


def _canonical_json_object_keys(value: object) -> frozenset[str]:
    items = _canonical_json_object_items(value)
    keys = tuple(key for key, _ in items)
    unique = frozenset(keys)
    if len(keys) != len(unique):
        _invalid()
    return unique


def _canonical_json_object_value(value: object, field_name: str) -> object:
    items = _canonical_json_object_items(value)
    keys = tuple(key for key, _ in items)
    if len(keys) != len(frozenset(keys)):
        _invalid()
    for key, item in items:
        if key == field_name:
            return item
    raise KeyError(field_name)


def _canonical_json_object_to_plain(value: object) -> object:
    if (
        type(value) is tuple
        and len(value) == 2
        and tuple.__getitem__(value, 0) == ("trusted-time-canonical-json-object-v1")
    ):
        items = _canonical_json_object_items(value)
        keys = tuple(key for key, _ in items)
        if len(keys) != len(frozenset(keys)):
            _invalid()
        return {key: _canonical_json_object_to_plain(item) for key, item in items}
    if value is None or type(value) in {bool, int, str}:
        return value
    _invalid()


def _decode_canonical_object(encoded: object, *, maximum_bytes: int) -> _CanonicalJsonObject:
    if type(encoded) is not bytes or not encoded or len(encoded) > maximum_bytes:
        _invalid()
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _invalid(),
            parse_int=_bounded_json_integer,
            parse_float=lambda _: _invalid(),
        )
        _require_bounded_json_tree(payload)
        canonical = _canonical_json_object_bytes(payload)
    except (RecursionError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _invalid()
    try:
        _canonical_json_object_items(payload)
    except _InvalidLocator:
        _invalid()
    if canonical != encoded:
        _invalid()
    return cast(_CanonicalJsonObject, payload)


def _persistent_container(
    payload: object,
    *,
    expected_service: str,
) -> _PersistentContainerProjection:
    if _canonical_json_object_keys(payload) != _CONTAINER_FIELDS:
        _invalid()
    try:
        projection: _PersistentContainerProjection = (
            "trusted-time-persistent-container-projection-v1",
            cast(str, _canonical_json_object_value(payload, "service")),
            cast(str, _canonical_json_object_value(payload, "container_id")),
            cast(str, _canonical_json_object_value(payload, "image_id")),
            cast(
                str,
                _canonical_json_object_value(payload, "stable_inspection_projection_sha256"),
            ),
            cast(
                str,
                _canonical_json_object_value(payload, "running_state_projection_sha256"),
            ),
            cast(
                str,
                _canonical_json_object_value(payload, "image_configuration_projection_sha256"),
            ),
        )
    except (KeyError, TypeError, ValueError):
        _invalid()
    if (
        _persistent_container_slot(projection, 1) != expected_service
        or not _is_container_id(_persistent_container_slot(projection, 2))
        or not _is_image_id(_persistent_container_slot(projection, 3))
        or not _is_sha256(_persistent_container_slot(projection, 4))
        or not _is_sha256(_persistent_container_slot(projection, 5))
        or not _is_sha256(_persistent_container_slot(projection, 6))
    ):
        _invalid()
    return projection


def _validate_persistent_topology_payload(
    payload: object,
) -> _PersistentTopologyProjection:
    expected_fields = {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *_PERSISTENT_TOPOLOGY_CLOSED_FIELDS,
        *_PERSISTENT_TOPOLOGY_FIELDS,
    }
    if _canonical_json_object_keys(payload) != expected_fields:
        _invalid()
    value = payload
    get = _canonical_json_object_value
    if (
        any(get(value, field_name) is not False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS)
        or any(
            get(value, field_name) is not False for field_name in _PERSISTENT_TOPOLOGY_CLOSED_FIELDS
        )
        or get(value, "contract_version") != POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION
        or get(value, "status") != POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS
        or get(value, "service") != POST_ENROLLMENT_START_SERVICE
        or get(value, "compose_project") != POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT
        or get(value, "submitted_project_container_count") != 2
        or not _is_uuid4(get(value, "operation_id"))
    ):
        _invalid()
    digest_fields = (
        "active_controller_admission_sha256",
        "approval_sha256",
        "claim_sha256",
        "created_topology_snapshot_sha256",
        "database_secret_consumed_candidate_sha256",
        "final_action_snapshot_sha256",
        "final_action_stable_topology_sha256",
        "network_id",
        "network_projection_sha256",
        "release_marker_candidate_sha256",
        "release_staging_absence_candidate_sha256",
        "retained_claim_artifact_sha256",
        "staged_input_retirement_candidate_sha256",
        "successor_candidate_sha256",
    )
    if any(not _is_sha256(get(value, field_name)) for field_name in digest_fields):
        _invalid()

    approved_launch = get(value, "approved_launch")
    if _canonical_json_object_keys(approved_launch) != {
        "git_revision",
        "image_admission_sha256",
        "source_image_id",
        "supervisor_image_id",
    }:
        _invalid()
    git_revision = get(approved_launch, "git_revision")
    image_admission_sha256 = get(approved_launch, "image_admission_sha256")
    source_image_id = get(approved_launch, "source_image_id")
    supervisor_image_id = get(approved_launch, "supervisor_image_id")
    if (
        not _is_git_revision(git_revision)
        or not _is_sha256(image_admission_sha256)
        or not _is_image_id(source_image_id)
        or not _is_image_id(supervisor_image_id)
        or source_image_id == supervisor_image_id
    ):
        _invalid()

    daemon = get(value, "daemon_identity")
    if _canonical_json_object_keys(daemon) != {
        "context_name",
        "daemon_id",
        "endpoint",
    }:
        _invalid()
    if not _valid_daemon_identity_values(
        get(daemon, "context_name"),
        get(daemon, "endpoint"),
        get(daemon, "daemon_id"),
    ):
        _invalid()

    volumes = get(value, "volume_identities")
    if _canonical_json_object_keys(volumes) != {
        "socket_sha256",
        "state_sha256",
    }:
        _invalid()
    if any(
        not _is_sha256(get(volumes, field_name)) for field_name in ("socket_sha256", "state_sha256")
    ):
        _invalid()

    source = _persistent_container(get(value, "source_container"), expected_service=_SOURCE_SERVICE)
    supervisor = _persistent_container(
        get(value, "supervisor_container"), expected_service=_SUPERVISOR_SERVICE
    )
    if (
        _persistent_container_slot(source, 2) == _persistent_container_slot(supervisor, 2)
        or _persistent_container_slot(source, 3) != source_image_id
        or _persistent_container_slot(supervisor, 3) != supervisor_image_id
    ):
        _invalid()
    return (
        "trusted-time-persistent-topology-projection-v1",
        cast(_CanonicalJsonObject, value),
        cast(str, get(value, "operation_id")),
        cast(str, get(value, "approval_sha256")),
        cast(str, get(value, "claim_sha256")),
        cast(
            str,
            get(value, "retained_claim_artifact_sha256"),
        ),
        cast(
            str,
            get(value, "active_controller_admission_sha256"),
        ),
        cast(
            str,
            get(value, "successor_candidate_sha256"),
        ),
        cast(str, source_image_id),
        cast(str, supervisor_image_id),
        cast(str, git_revision),
        cast(str, image_admission_sha256),
    )


def _persistent_topology_from_encoded(encoded: bytes) -> dict[str, object]:
    projection = _validate_persistent_topology_payload(
        _decode_canonical_object(encoded, maximum_bytes=_MAXIMUM_PERSISTENT_TOPOLOGY_BYTES)
    )
    plain = _canonical_json_object_to_plain(_persistent_topology_slot(projection, 1))
    if type(plain) is not dict:
        _invalid()
    return cast(dict[str, object], plain)


def _persistent_topology_binding_values_from_encoded(
    encoded: bytes,
) -> tuple[str, ...]:
    projection = _validate_persistent_topology_payload(
        _decode_canonical_object(encoded, maximum_bytes=_MAXIMUM_PERSISTENT_TOPOLOGY_BYTES)
    )
    return (
        cast(str, _persistent_topology_slot(projection, 2)),
        cast(str, _persistent_topology_slot(projection, 3)),
        cast(str, _persistent_topology_slot(projection, 4)),
        cast(str, _persistent_topology_slot(projection, 5)),
        cast(str, _persistent_topology_slot(projection, 6)),
        cast(str, _persistent_topology_slot(projection, 7)),
        cast(str, _persistent_topology_slot(projection, 8)),
        cast(str, _persistent_topology_slot(projection, 9)),
        cast(str, _persistent_topology_slot(projection, 10)),
        cast(str, _persistent_topology_slot(projection, 11)),
    )


@_stage_post_enrollment_shutdown_locator_type
@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentGracefulStopShutdownLocator:
    """Immutable non-authorizing locator embedded in a terminal start outcome."""

    active_controller_session_sha256: str
    network_name: str
    socket_volume_name: str
    state_volume_name: str
    persistent_topology_sha256: str
    persistent_topology_transcript_sha256: str
    persistent_topology_encoded: bytes = field(repr=False)

    def __post_init__(self) -> None:
        try:
            topology = _persistent_topology_from_encoded(self.persistent_topology_encoded)
            if (
                type(self) is not TrustedTimePostEnrollmentGracefulStopShutdownLocator
                or not _is_sha256(self.active_controller_session_sha256)
                or self.network_name
                != post_enrollment_created_topology_network_name(
                    self.active_controller_session_sha256
                )
                or self.socket_volume_name != COMPOSE_SOCKET_VOLUME_NAME
                or self.state_volume_name != COMPOSE_STATE_VOLUME_NAME
                or not _is_sha256(self.persistent_topology_sha256)
                or hashlib.sha256(self.persistent_topology_encoded).hexdigest()
                != self.persistent_topology_sha256
                or not _is_sha256(self.persistent_topology_transcript_sha256)
                or topology["contract_version"]
                != POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION
            ):
                _invalid()
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected(
                "trusted-time post-enrollment shutdown locator is invalid"
            ) from None

    @property
    def persistent_topology(self) -> dict[str, object]:
        self.__post_init__()
        return _persistent_topology_from_encoded(self.persistent_topology_encoded)

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload: dict[str, object] = {
            field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        }
        payload.update({field_name: False for field_name in _CLOSED_FIELDS})
        payload.update(
            {
                "active_controller_session_sha256": (self.active_controller_session_sha256),
                "contract_version": (
                    POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION
                ),
                "network_name": self.network_name,
                "persistent_topology": self.persistent_topology,
                "persistent_topology_sha256": self.persistent_topology_sha256,
                "persistent_topology_transcript_sha256": (
                    self.persistent_topology_transcript_sha256
                ),
                "service": POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_SERVICE,
                "socket_volume_name": self.socket_volume_name,
                "state_volume_name": self.state_volume_name,
                "status": POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS,
            }
        )
        return payload

    active_controller_authorized = property(lambda _: False)
    authority_granted = property(lambda _: False)
    claim_retention_authorized = property(lambda _: False)
    clean_stop_authorized = property(lambda _: False)
    container_removal_authorized = property(lambda _: False)
    controller_execution_authorized = property(lambda _: False)
    database_secret_disclosed = property(lambda _: False)
    execution_admission_authorized = property(lambda _: False)
    execution_attempt_reservation_authorized = property(lambda _: False)
    network_removal_authorized = property(lambda _: False)
    outcome_retention_authorized = property(lambda _: False)
    persistent_start_authorized = property(lambda _: False)
    qualified = property(lambda _: False)
    release_authorized = property(lambda _: False)
    retry_authorized = property(lambda _: False)
    runtime_start_authorized = property(lambda _: False)
    sequence_2_authorized = property(lambda _: False)
    shutdown_authorized = property(lambda _: False)
    source_stop_authorized = property(lambda _: False)
    source_start_authorized = property(lambda _: False)
    success_outcome_retention_authorized = property(lambda _: False)
    supervisor_signal_authorized = property(lambda _: False)
    supervisor_stop_authorized = property(lambda _: False)
    supervisor_start_authorized = property(lambda _: False)
    teardown_authorized = property(lambda _: False)
    topology_mutation_authorized = property(lambda _: False)
    volume_removal_authorized = property(lambda _: False)


def build_post_enrollment_graceful_stop_shutdown_locator(
    *,
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    persistent_topology: TrustedTimePostEnrollmentPersistentTopologySnapshot,
    persistent_topology_transcript_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopShutdownLocator:
    """Bind one live controller topology into inert durable locator evidence."""

    try:
        if (
            type(admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
            or type(persistent_topology) is not TrustedTimePostEnrollmentPersistentTopologySnapshot
            or persistent_topology._admission is not admission
            or not _is_sha256(persistent_topology_transcript_sha256)
        ):
            _invalid()
        admission.__post_init__()
        persistent_topology.__post_init__()
        topology_encoded = canonical_first_enrollment_json_bytes(persistent_topology.payload())
        if len(topology_encoded) > _MAXIMUM_PERSISTENT_TOPOLOGY_BYTES:
            _invalid()
        locator = TrustedTimePostEnrollmentGracefulStopShutdownLocator(
            active_controller_session_sha256=admission.session_sha256,
            network_name=post_enrollment_created_topology_network_name(admission.session_sha256),
            socket_volume_name=COMPOSE_SOCKET_VOLUME_NAME,
            state_volume_name=COMPOSE_STATE_VOLUME_NAME,
            persistent_topology_sha256=persistent_topology.snapshot_sha256,
            persistent_topology_transcript_sha256=persistent_topology_transcript_sha256,
            persistent_topology_encoded=topology_encoded,
        )
        canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
        return locator
    except TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected(
            "trusted-time post-enrollment shutdown locator is invalid"
        ) from None


def canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(
    locator: object,
) -> bytes:
    """Return the exact bounded canonical bytes for one shutdown locator."""

    try:
        if type(locator) is not TrustedTimePostEnrollmentGracefulStopShutdownLocator:
            _invalid()
        locator.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(locator.payload())
        if (
            not encoded
            or len(encoded) > POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES
        ):
            _invalid()
        return encoded
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected(
            "trusted-time post-enrollment shutdown locator is invalid"
        ) from None


def post_enrollment_graceful_stop_shutdown_locator_sha256(locator: object) -> str:
    """Return the content identity of one exact canonical locator."""

    return hashlib.sha256(
        canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    ).hexdigest()


def _shutdown_locator_projection_from_encoded(
    encoded: object,
) -> _ShutdownLocatorProjection:
    payload = _decode_canonical_object(
        encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES,
    )
    expected_fields = {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *_CLOSED_FIELDS,
        *_FIELDS,
    }
    get = _canonical_json_object_value
    if (
        _canonical_json_object_keys(payload) != expected_fields
        or any(
            get(payload, field_name) is not False
            for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        )
        or any(get(payload, field_name) is not False for field_name in _CLOSED_FIELDS)
        or get(payload, "contract_version")
        != POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION
        or get(payload, "service") != POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_SERVICE
        or get(payload, "status") != POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS
    ):
        _invalid()
    topology = get(payload, "persistent_topology")
    topology_encoded = _canonical_json_object_bytes(topology)
    topology_projection = _validate_persistent_topology_payload(
        cast(_CanonicalJsonObject, topology)
    )
    active_controller_session_sha256 = get(payload, "active_controller_session_sha256")
    network_name = get(payload, "network_name")
    socket_volume_name = get(payload, "socket_volume_name")
    state_volume_name = get(payload, "state_volume_name")
    persistent_topology_sha256 = get(payload, "persistent_topology_sha256")
    persistent_topology_transcript_sha256 = get(
        payload,
        "persistent_topology_transcript_sha256",
    )
    if (
        not _is_sha256(active_controller_session_sha256)
        or type(network_name) is not str
        or network_name
        != post_enrollment_created_topology_network_name(
            cast(str, active_controller_session_sha256)
        )
        or type(socket_volume_name) is not str
        or socket_volume_name != COMPOSE_SOCKET_VOLUME_NAME
        or type(state_volume_name) is not str
        or state_volume_name != COMPOSE_STATE_VOLUME_NAME
        or type(persistent_topology_sha256) is not str
        or not _is_sha256(persistent_topology_sha256)
        or hashlib.sha256(topology_encoded).hexdigest() != persistent_topology_sha256
        or not _is_sha256(persistent_topology_transcript_sha256)
        or _canonical_json_object_bytes(payload) != encoded
        or _persistent_topology_slot(topology_projection, 1) is not topology
    ):
        _invalid()
    return (
        "trusted-time-shutdown-locator-projection-v1",
        cast(str, active_controller_session_sha256),
        network_name,
        socket_volume_name,
        state_volume_name,
        persistent_topology_sha256,
        cast(
            str,
            persistent_topology_transcript_sha256,
        ),
        topology_encoded,
        (
            cast(str, _persistent_topology_slot(topology_projection, 2)),
            cast(str, _persistent_topology_slot(topology_projection, 3)),
            cast(str, _persistent_topology_slot(topology_projection, 4)),
            cast(
                str,
                _persistent_topology_slot(
                    topology_projection,
                    5,
                ),
            ),
            cast(
                str,
                _persistent_topology_slot(
                    topology_projection,
                    6,
                ),
            ),
            cast(str, _persistent_topology_slot(topology_projection, 7)),
            cast(str, _persistent_topology_slot(topology_projection, 8)),
            cast(
                str,
                _persistent_topology_slot(topology_projection, 9),
            ),
            cast(str, _persistent_topology_slot(topology_projection, 10)),
            cast(
                str,
                _persistent_topology_slot(
                    topology_projection,
                    11,
                ),
            ),
        ),
    )


def decode_post_enrollment_graceful_stop_shutdown_locator(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopShutdownLocator:
    """Strictly decode one canonical locator without granting authority."""

    try:
        projection = _shutdown_locator_projection_from_encoded(encoded)
        locator = TrustedTimePostEnrollmentGracefulStopShutdownLocator(
            active_controller_session_sha256=cast(
                str,
                _shutdown_locator_slot(projection, 1),
            ),
            network_name=cast(str, _shutdown_locator_slot(projection, 2)),
            socket_volume_name=cast(
                str,
                _shutdown_locator_slot(projection, 3),
            ),
            state_volume_name=cast(
                str,
                _shutdown_locator_slot(projection, 4),
            ),
            persistent_topology_sha256=cast(
                str,
                _shutdown_locator_slot(projection, 5),
            ),
            persistent_topology_transcript_sha256=cast(
                str,
                _shutdown_locator_slot(
                    projection,
                    6,
                ),
            ),
            persistent_topology_encoded=cast(
                bytes,
                _shutdown_locator_slot(projection, 7),
            ),
        )
        if (
            locator.active_controller_session_sha256 != _shutdown_locator_slot(projection, 1)
            or locator.network_name != _shutdown_locator_slot(projection, 2)
            or locator.socket_volume_name != _shutdown_locator_slot(projection, 3)
            or locator.state_volume_name != _shutdown_locator_slot(projection, 4)
            or locator.persistent_topology_sha256 != _shutdown_locator_slot(projection, 5)
            or locator.persistent_topology_transcript_sha256
            != _shutdown_locator_slot(
                projection,
                6,
            )
            or locator.persistent_topology_encoded != _shutdown_locator_slot(projection, 7)
        ):
            _invalid()
        return locator
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected(
            "trusted-time post-enrollment shutdown locator is invalid"
        ) from None


_finalize_post_enrollment_shutdown_locator_projection_type()

del _finalize_post_enrollment_shutdown_locator_projection_type
del _stage_post_enrollment_shutdown_locator_type


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_STATUS",
    "TrustedTimePostEnrollmentGracefulStopShutdownLocator",
    "TrustedTimePostEnrollmentGracefulStopShutdownLocatorRejected",
    "build_post_enrollment_graceful_stop_shutdown_locator",
    "canonical_post_enrollment_graceful_stop_shutdown_locator_bytes",
    "decode_post_enrollment_graceful_stop_shutdown_locator",
    "post_enrollment_graceful_stop_shutdown_locator_sha256",
]
