"""Unreachable lifecycle-v2 evidence core for ADR 0121 milestone one.

This module defines canonical, effect-free evidence values.  It deliberately
does not open an artifact root, connect a transport, call Docker, authenticate
a signature, or grant graceful-stop authority.  The separately injected
repository and test fakes are the only milestone-one consumers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Never, Self, cast

LIFECYCLE_V2_ROOT_CONTRACT_VERSION = "phase6d-post-enrollment-graceful-stop-lifecycle-root-v2"
LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION = "phase6d-post-enrollment-graceful-stop-lifecycle-record-v2"
LIFECYCLE_V2_TRANSCRIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-lifecycle-transcript-v2"
)
LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION = "phase6d-post-enrollment-graceful-stop-lifecycle-outcome-v2"
LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-lifecycle-outcome-commit-v2"
)
LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-transport-envelope-v2"
)
LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION = (
    "phase6d-trusted-time-head-anchor-clean-stop-request-basis-v2"
)
LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION = (
    "phase6d-trusted-time-head-anchor-clean-stop-request-v2"
)
LIFECYCLE_V2_SERVICE = "trusted-time-post-enrollment-graceful-stop-lifecycle-v2"
LIFECYCLE_V2_TRANSPORT_SERVICE = "trusted-time-graceful-stop-transport-v2"
LIFECYCLE_V2_CLEAN_STOP_SERVICE = "trusted-time-head-anchor-clean-stop-v2"

LIFECYCLE_ROOT_FILE_NAME = ".post-enrollment-graceful-stop-attempt-slot"
LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME = ".post-enrollment-graceful-stop-outcome-committed-v2"
LIFECYCLE_V2_ROOT_MAXIMUM_BYTES = 64 * 1_024
LIFECYCLE_V2_RECORD_MAXIMUM_BYTES = 256 * 1_024
LIFECYCLE_V2_TRANSCRIPT_MAXIMUM_BYTES = 256 * 1_024
LIFECYCLE_V2_OUTCOME_MAXIMUM_BYTES = 256 * 1_024
LIFECYCLE_V2_WIRE_MAXIMUM_BYTES = 262_144
LIFECYCLE_V2_MAXIMUM_ENTRIES = 64
LIFECYCLE_V2_MAXIMUM_DEPTH = 12
LIFECYCLE_V2_MAXIMUM_NODES = 4_096
LIFECYCLE_V2_OPERATION_BUDGET_NS = 600_000_000_000
LIFECYCLE_V2_COMMIT_BUDGET_NS = 5_000_000_000
MAXIMUM_SIGNED_INTEGER = 2**63 - 1

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_ASCII_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY = object()


class TrustedTimeGracefulStopV2Rejected(ValueError):
    """Canonical v2 evidence is malformed, mixed, replayed, or out of order."""


class LifecycleV2Stage(StrEnum):
    ROOT_RESERVED = "root_reserved"
    CLEAN_STOP_REQUEST_INTENT_RETAINED = "clean_stop_request_intent_retained"
    CLEAN_STOP_RESULT_RETAINED = "clean_stop_result_retained"
    CLEAN_STOP_ERROR_RETAINED = "clean_stop_error_retained"
    TRANSPORT_CLEANUP_COMMITMENT_RETAINED = "transport_cleanup_commitment_retained"
    TRANSPORT_CHANNEL_QUIESCED = "transport_channel_quiesced"
    PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED = "pre_effect_reauthentication_intent_retained"
    PRE_EFFECT_REAUTHENTICATION_BOUND = "pre_effect_reauthentication_bound"
    SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED = "supervisor_container_stop_intent_retained"
    SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED = "supervisor_container_stop_result_retained"
    SOURCE_CONTAINER_STOP_INTENT_RETAINED = "source_container_stop_intent_retained"
    SOURCE_CONTAINER_STOP_RESULT_RETAINED = "source_container_stop_result_retained"
    SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED = "supervisor_container_remove_intent_retained"
    SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED = "supervisor_container_remove_result_retained"
    SOURCE_CONTAINER_REMOVE_INTENT_RETAINED = "source_container_remove_intent_retained"
    SOURCE_CONTAINER_REMOVE_RESULT_RETAINED = "source_container_remove_result_retained"
    PROJECT_NETWORK_REMOVE_INTENT_RETAINED = "project_network_remove_intent_retained"
    PROJECT_NETWORK_REMOVE_RESULT_RETAINED = "project_network_remove_result_retained"
    NAMED_VOLUME_PRESERVATION_INTENT_RETAINED = "named_volume_preservation_intent_retained"
    NAMED_VOLUMES_PRESERVED = "named_volumes_preserved"
    POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED = (
        "post_teardown_reauthentication_intent_retained"
    )
    POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND = "post_teardown_terminal_reauthentication_bound"
    TERMINAL_CLEANUP_INTENT_RETAINED = "terminal_cleanup_intent_retained"
    TERMINAL_CLEANUP_CONFIRMED = "terminal_cleanup_confirmed"
    RECOVERY_CLASSIFICATION_INTENT_RETAINED = "recovery_classification_intent_retained"


NORMAL_STAGE_BY_ORDINAL: dict[int, LifecycleV2Stage] = {
    0: LifecycleV2Stage.ROOT_RESERVED,
    1: LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
    2: LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
    3: LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
    4: LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED,
    5: LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
    6: LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
    7: LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
    8: LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
    9: LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
    10: LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
    11: LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
    12: LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
    13: LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
    14: LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
    15: LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
    16: LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
    17: LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
    18: LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
    19: LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
    20: LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
    21: LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED,
    22: LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED,
}


def _reject_float(_: str) -> Never:
    raise TrustedTimeGracefulStopV2Rejected("floating point JSON is forbidden")


def _reject_constant(_: str) -> Never:
    raise TrustedTimeGracefulStopV2Rejected("non-finite JSON is forbidden")


def _parse_integer(value: str) -> int:
    parsed = int(value)
    if parsed < -MAXIMUM_SIGNED_INTEGER - 1 or parsed > MAXIMUM_SIGNED_INTEGER:
        raise TrustedTimeGracefulStopV2Rejected("JSON integer is outside signed 64-bit bounds")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrustedTimeGracefulStopV2Rejected("duplicate JSON key")
        result[key] = value
    return result


def _bounded_tree(value: object) -> None:
    nodes = 0

    def visit(node: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > LIFECYCLE_V2_MAXIMUM_NODES or depth > LIFECYCLE_V2_MAXIMUM_DEPTH:
            raise TrustedTimeGracefulStopV2Rejected("canonical JSON tree exceeds its bounds")
        if node is None or type(node) in (bool, int, str):
            if type(node) is str and len(node.encode("utf-8")) > 65_536:
                raise TrustedTimeGracefulStopV2Rejected("canonical JSON string is too large")
            return
        if type(node) is list:
            for item in node:
                visit(item, depth + 1)
            return
        if type(node) is dict:
            for key, item in node.items():
                if type(key) is not str:
                    raise TrustedTimeGracefulStopV2Rejected("JSON object key is not text")
                visit(item, depth + 1)
            return
        raise TrustedTimeGracefulStopV2Rejected("unsupported canonical JSON value")

    visit(value, 0)


def canonical_v2_json_bytes(value: object, *, maximum_bytes: int) -> bytes:
    """Encode one already-validated JSON value under ADR-0121 canonical rules."""

    _bounded_tree(value)
    try:
        encoded = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise TrustedTimeGracefulStopV2Rejected("value is not canonical JSON") from error
    if len(encoded) > maximum_bytes:
        raise TrustedTimeGracefulStopV2Rejected("canonical artifact exceeds its byte bound")
    return encoded


def decode_canonical_v2_json_object(
    encoded: object,
    *,
    maximum_bytes: int,
) -> dict[str, object]:
    """Decode, bound, and byte-for-byte revalidate one canonical JSON object."""

    if type(encoded) is not bytes or not encoded or len(encoded) > maximum_bytes:
        raise TrustedTimeGracefulStopV2Rejected("canonical artifact has an invalid byte length")
    try:
        decoded = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except TrustedTimeGracefulStopV2Rejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrustedTimeGracefulStopV2Rejected("canonical artifact is invalid JSON") from error
    if type(decoded) is not dict:
        raise TrustedTimeGracefulStopV2Rejected("canonical artifact must be one object")
    _bounded_tree(decoded)
    if canonical_v2_json_bytes(decoded, maximum_bytes=maximum_bytes) != encoded:
        raise TrustedTimeGracefulStopV2Rejected("artifact bytes are not canonical")
    return decoded


def _require_fields(value: dict[str, object], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        raise TrustedTimeGracefulStopV2Rejected("artifact field set is not exact")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_sha256(domain: str, encoded: bytes) -> str:
    return _sha256(domain.encode("ascii") + b"\0" + encoded)


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} must be lowercase SHA-256")
    return value


def _require_identifier(value: object, name: str) -> str:
    if type(value) is not str or _ASCII_IDENTIFIER.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} must be a bounded ASCII identifier")
    return value


def _require_int(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > MAXIMUM_SIGNED_INTEGER:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is outside its integer bounds")
    return value


def _require_utc(value: object, name: str) -> str:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical UTC")
    return value


def _require_exact_deadline(start: object, deadline: object) -> tuple[int, int]:
    exact_start = _require_int(start, "admission_started_boottime_ns")
    exact_deadline = _require_int(deadline, "operation_deadline_boottime_ns")
    if exact_start > MAXIMUM_SIGNED_INTEGER - LIFECYCLE_V2_OPERATION_BUDGET_NS:
        raise TrustedTimeGracefulStopV2Rejected("operation deadline addition overflows")
    if exact_deadline != exact_start + LIFECYCLE_V2_OPERATION_BUDGET_NS:
        raise TrustedTimeGracefulStopV2Rejected("operation deadline is not the checked sum")
    return exact_start, exact_deadline


@dataclass(frozen=True, slots=True)
class FrozenJsonObject:
    """An immutable, canonically sorted nested JSON object."""

    entries: tuple[tuple[str, object], ...]

    @classmethod
    def capture(cls, value: object) -> Self:
        if type(value) is not dict:
            raise TrustedTimeGracefulStopV2Rejected("evidence must be one exact JSON object")
        _bounded_tree(value)
        entries = tuple(
            (key, _freeze_json(item))
            for key, item in sorted(value.items(), key=lambda pair: pair[0])
        )
        return cls(entries)

    def to_dict(self) -> dict[str, object]:
        return {key: _thaw_json(value) for key, value in self.entries}


def _freeze_json(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    if type(value) is dict:
        return FrozenJsonObject.capture(value)
    raise TrustedTimeGracefulStopV2Rejected("unsupported evidence value")


def _thaw_json(value: object) -> object:
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    if type(value) is FrozenJsonObject:
        return value.to_dict()
    return value


_ROOT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "lifecycle_version",
        "phase",
        "ordinal",
        "environment",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operator_attestation_envelope_sha256",
        "historical_decision_receipt_sha256",
        "admission_sha256",
        "topology_sha256",
        "topology_lease_sha256",
        "trusted_head_sha256",
        "stop_authority_sha256",
        "transport_authority_manifest_sha256",
        "transport_key_generation",
        "host_transport_key_id",
        "supervisor_transport_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "channel_id",
        "supervisor_container_id",
        "source_container_id",
        "project_network_id",
        "chrony_command_socket_volume_identity_sha256",
        "chrony_state_volume_identity_sha256",
        "admission_started_boottime_ns",
        "clean_stop_result_deadline_boottime_ns",
        "operation_deadline_boottime_ns",
        "root_created_at_utc",
    }
)


@dataclass(frozen=True, slots=True)
class LifecycleV2Root:
    environment: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operator_attestation_envelope_sha256: str
    historical_decision_receipt_sha256: str
    admission_sha256: str
    topology_sha256: str
    topology_lease_sha256: str
    trusted_head_sha256: str
    stop_authority_sha256: str
    transport_authority_manifest_sha256: str
    transport_key_generation: int
    host_transport_key_id: str
    supervisor_transport_key_id: str
    boot_epoch_sha256: str
    host_process_epoch_sha256: str
    supervisor_process_epoch_sha256: str
    channel_id: str
    supervisor_container_id: str
    source_container_id: str
    project_network_id: str
    chrony_command_socket_volume_identity_sha256: str
    chrony_state_volume_identity_sha256: str
    admission_started_boottime_ns: int
    clean_stop_result_deadline_boottime_ns: int
    operation_deadline_boottime_ns: int
    root_created_at_utc: str

    def __post_init__(self) -> None:
        _require_identifier(self.environment, "environment")
        _require_identifier(self.graceful_stop_operation_id, "graceful_stop_operation_id")
        for name in (
            "graceful_stop_target_sha256",
            "graceful_stop_decision_v1_sha256",
            "graceful_stop_operator_attestation_envelope_sha256",
            "historical_decision_receipt_sha256",
            "admission_sha256",
            "topology_sha256",
            "topology_lease_sha256",
            "trusted_head_sha256",
            "stop_authority_sha256",
            "transport_authority_manifest_sha256",
            "boot_epoch_sha256",
            "host_process_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "channel_id",
            "chrony_command_socket_volume_identity_sha256",
            "chrony_state_volume_identity_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        _require_int(self.transport_key_generation, "transport_key_generation", minimum=1)
        _require_identifier(self.host_transport_key_id, "host_transport_key_id")
        _require_identifier(self.supervisor_transport_key_id, "supervisor_transport_key_id")
        for name in ("supervisor_container_id", "source_container_id", "project_network_id"):
            _require_sha256(getattr(self, name), name)
        start, operation_deadline = _require_exact_deadline(
            self.admission_started_boottime_ns,
            self.operation_deadline_boottime_ns,
        )
        result_deadline = _require_int(
            self.clean_stop_result_deadline_boottime_ns,
            "clean_stop_result_deadline_boottime_ns",
        )
        if not start < result_deadline < operation_deadline:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop deadline is outside admission")
        _require_utc(self.root_created_at_utc, "root_created_at_utc")

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "graceful_stop_lifecycle_v2_reserved",
            "lifecycle_version": 2,
            "phase": LifecycleV2Stage.ROOT_RESERVED.value,
            "ordinal": 0,
            **{name: getattr(self, name) for name in _ROOT_FIELDS if hasattr(self, name)},
        }

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=LIFECYCLE_V2_ROOT_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_root(encoded: object) -> LifecycleV2Root:
    value = decode_canonical_v2_json_object(encoded, maximum_bytes=LIFECYCLE_V2_ROOT_MAXIMUM_BYTES)
    _require_fields(value, _ROOT_FIELDS)
    if (
        value["contract_version"] != LIFECYCLE_V2_ROOT_CONTRACT_VERSION
        or value["service"] != LIFECYCLE_V2_SERVICE
        or value["status"] != "graceful_stop_lifecycle_v2_reserved"
        or value["lifecycle_version"] != 2
        or value["phase"] != LifecycleV2Stage.ROOT_RESERVED.value
        or type(value["ordinal"]) is not int
        or value["ordinal"] != 0
    ):
        raise TrustedTimeGracefulStopV2Rejected("root discriminator is not lifecycle v2")
    kwargs = {
        name: value[name]
        for name in _ROOT_FIELDS
        if name
        not in {"contract_version", "service", "status", "lifecycle_version", "phase", "ordinal"}
    }
    return LifecycleV2Root(**kwargs)  # type: ignore[arg-type]


_PROGRESS_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "lifecycle_version",
        "graceful_stop_operation_id",
        "root_sha256",
        "ordinal",
        "stage",
        "predecessor_sha256",
        "effect_kind",
        "deadline_boottime_ns",
        "evidence",
        "recorded_at_utc",
    }
)
_INTENT_EVIDENCE_FIELDS = frozenset(
    {
        "target_identity_sha256",
        "arguments_sha256",
        "admission_sha256",
        "channel_id",
        "call_deadline_boottime_ns",
    }
)
_REQUEST_INTENT_EVIDENCE_FIELDS = _INTENT_EVIDENCE_FIELDS | {
    "admission_started_boottime_ns",
    "operation_deadline_boottime_ns",
}
_RESULT_EVIDENCE_FIELDS = frozenset(
    {
        "intent_sha256",
        "responder_identity_sha256",
        "disposition",
        "result_semantic_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
    }
)
_REAUTHENTICATION_RESULT_EXTRA_FIELDS = frozenset(
    {
        "observation_semantic_sha256",
        "binding_semantic_sha256",
        "observed_head_sha256",
        "provider_identity_sha256",
    }
)
_DOCKER_INTENT_EXTRA_FIELDS = frozenset(
    {"docker_request_semantic_sha256", "docker_post_inspect_request_semantic_sha256"}
)
_DOCKER_RESULT_EXTRA_FIELDS = frozenset(
    {
        "docker_request_semantic_sha256",
        "docker_post_inspect_request_semantic_sha256",
        "result_semantic",
        "docker_method_trace_entry_sha256_list",
    }
)
_VOLUME_INTENT_EXTRA_FIELDS = frozenset({"docker_request_semantic_sha256_list"})
_VOLUME_RESULT_EXTRA_FIELDS = frozenset(
    {
        "command_socket_volume_identity_sha256",
        "state_volume_identity_sha256",
        "docker_api_trace_sha256",
        "volume_delete_call_count",
        "docker_request_semantic_sha256_list",
        "result_semantic",
        "docker_method_trace_entry_sha256_list",
    }
)
_WIRE_RESULT_EVIDENCE_FIELDS = frozenset(
    {
        "intent_sha256",
        "responder_identity_sha256",
        "disposition",
        "clean_stop_result_artifact_path",
        "clean_stop_result_artifact_name",
        "clean_stop_result_sha256",
        "envelope_contract_version",
        "frame_type",
        "payload_contract_version",
        "clean_stop_result_payload_sha256",
        "clean_stop_result_signature_sha256",
        "terminal_projection_sha256",
        "key_generation",
        "signing_key_id",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "message_counter",
        "deadline_boottime_ns",
        "wire_publication_receipt",
        "wire_publication_receipt_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
    }
)
_WIRE_ERROR_EVIDENCE_FIELDS = frozenset(
    {
        "intent_sha256",
        "responder_identity_sha256",
        "disposition",
        "clean_stop_error_artifact_path",
        "clean_stop_error_artifact_name",
        "clean_stop_error_sha256",
        "envelope_contract_version",
        "frame_type",
        "payload_contract_version",
        "clean_stop_error_payload_sha256",
        "clean_stop_error_signature_sha256",
        "key_generation",
        "signing_key_id",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "message_counter",
        "deadline_boottime_ns",
        "wire_publication_receipt",
        "wire_publication_receipt_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "error_code",
        "failure_boundary",
    }
)
_TRANSPORT_COMMITMENT_FIELDS = frozenset(
    {
        "clean_stop_result_sha256",
        "supervisor_cleanup_commitment_sha256",
        "channel_id",
        "host_process_epoch_sha256",
        "host_socket_identity_sha256",
        "host_peer_credential_sha256",
        "host_raw_key_path",
        "host_raw_key_device",
        "host_raw_key_inode",
        "host_challenge_sha256",
        "host_process_nonce_sha256",
        "cleanup_deadline_boottime_ns",
    }
)
_TRANSPORT_QUIESCENCE_FIELDS = frozenset(
    {
        "cleanup_commitment_record_sha256",
        "supervisor_cleanup_commitment_sha256",
        "host_native_cleanup_receipt_sha256",
        "supervisor_quiescence_observation_sha256",
        "channel_eof_observed",
        "listener_fd_absent",
        "accepted_fd_absent",
        "socket_path_absent",
        "host_signer_zeroized",
        "host_challenge_zeroized",
        "host_process_nonce_zeroized",
        "credential_paths_absent",
        "cleanup_started_boottime_ns",
        "cleanup_completed_boottime_ns",
    }
)
_TERMINAL_CLEANUP_INTENT_FIELDS = frozenset(
    {
        "transport_quiescence_record_sha256",
        "supervisor_remove_result_sha256",
        "transport_mount_identity_sha256",
        "host_secret_mount_identity_sha256",
        "supervisor_secret_mount_identity_sha256",
        "recovery_secret_mount_absence_sha256",
        "socket_path_absence_sha256",
        "credential_path_absence_sha256",
        "native_owner_set_sha256",
        "cleanup_deadline_boottime_ns",
    }
)
_TERMINAL_CLEANUP_RESULT_FIELDS = frozenset(
    {
        "cleanup_intent_sha256",
        "transport_quiescence_record_sha256",
        "supervisor_remove_result_sha256",
        "socket_absence_sha256",
        "credential_path_absence_sha256",
        "empty_mount_projection_sha256",
        "unmount_receipt_sha256",
        "native_owner_cleanup_receipt_sha256",
        "all_private_material_unreachable",
        "cleanup_completed_boottime_ns",
    }
)
_RECOVERY_INTENT_FIELDS = frozenset(
    {
        "recovery_classification_envelope_sha256",
        "operator_nonce_sha256",
        "recovery_key_id",
        "transport_authority_manifest_sha256",
        "classified_transcript_sha256",
        "admission_started_boottime_ns",
        "operation_deadline_boottime_ns",
        "reason_code",
    }
)

_INTENT_STAGES = frozenset(
    {
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
    }
)
_DOCKER_INTENT_STAGES = frozenset(
    {
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
    }
)
_DOCKER_RESULT_STAGES = frozenset(
    {
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
    }
)
_REAUTHENTICATION_RESULT_STAGES = frozenset(
    {
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
        LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
    }
)


def _expected_evidence_fields(stage: LifecycleV2Stage) -> frozenset[str]:
    if stage is LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED:
        return _REQUEST_INTENT_EVIDENCE_FIELDS
    if stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED:
        return _WIRE_RESULT_EVIDENCE_FIELDS
    if stage is LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED:
        return _WIRE_ERROR_EVIDENCE_FIELDS
    if stage is LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED:
        return _TRANSPORT_COMMITMENT_FIELDS
    if stage is LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED:
        return _TRANSPORT_QUIESCENCE_FIELDS
    if stage in _DOCKER_INTENT_STAGES:
        return _INTENT_EVIDENCE_FIELDS | _DOCKER_INTENT_EXTRA_FIELDS
    if stage in _INTENT_STAGES:
        return _INTENT_EVIDENCE_FIELDS
    if stage in _DOCKER_RESULT_STAGES:
        return _RESULT_EVIDENCE_FIELDS | _DOCKER_RESULT_EXTRA_FIELDS
    if stage in _REAUTHENTICATION_RESULT_STAGES:
        return _RESULT_EVIDENCE_FIELDS | _REAUTHENTICATION_RESULT_EXTRA_FIELDS
    if stage is LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED:
        return _INTENT_EVIDENCE_FIELDS | _VOLUME_INTENT_EXTRA_FIELDS
    if stage is LifecycleV2Stage.NAMED_VOLUMES_PRESERVED:
        return _RESULT_EVIDENCE_FIELDS | _VOLUME_RESULT_EXTRA_FIELDS
    if stage is LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED:
        return _TERMINAL_CLEANUP_INTENT_FIELDS
    if stage is LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED:
        return _TERMINAL_CLEANUP_RESULT_FIELDS
    if stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
        return _RECOVERY_INTENT_FIELDS
    raise TrustedTimeGracefulStopV2Rejected("stage has no milestone-one evidence schema")


def _validate_evidence(stage: LifecycleV2Stage, evidence: FrozenJsonObject) -> None:
    value = evidence.to_dict()
    _require_fields(value, _expected_evidence_fields(stage))
    for name, item in value.items():
        if name.endswith("_sha256"):
            _require_sha256(item, name)
        elif name.endswith("_sha256_list"):
            if type(item) is not list or not item:
                raise TrustedTimeGracefulStopV2Rejected(f"{name} must be a nonempty list")
            for digest in item:
                _require_sha256(digest, name)
    for name in (
        "call_deadline_boottime_ns",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "deadline_boottime_ns",
        "cleanup_deadline_boottime_ns",
        "cleanup_started_boottime_ns",
        "cleanup_completed_boottime_ns",
    ):
        if name in value:
            _require_int(value[name], name)
    if stage in _REAUTHENTICATION_RESULT_STAGES | _DOCKER_RESULT_STAGES | {
        LifecycleV2Stage.NAMED_VOLUMES_PRESERVED
    }:
        started = _require_int(value["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(value["call_completed_boottime_ns"], "call_completed_boottime_ns")
        if completed < started:
            raise TrustedTimeGracefulStopV2Rejected("result completion precedes call start")
    if stage is LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED:
        _require_exact_deadline(
            value["admission_started_boottime_ns"],
            value["operation_deadline_boottime_ns"],
        )
    if stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
        _require_exact_deadline(
            value["admission_started_boottime_ns"],
            value["operation_deadline_boottime_ns"],
        )
        _require_identifier(value["recovery_key_id"], "recovery_key_id")
        _require_identifier(value["reason_code"], "reason_code")
    if stage in {
        LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED,
        LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED,
    }:
        boolean_names = (
            _TRANSPORT_QUIESCENCE_FIELDS
            if stage is LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED
            else frozenset({"all_private_material_unreachable"})
        )
        for name in boolean_names:
            if (
                name in value
                and (
                    name.endswith("_observed")
                    or name.endswith("_absent")
                    or name.endswith("_zeroized")
                    or name == "credential_paths_absent"
                    or name == "all_private_material_unreachable"
                )
                and value[name] is not True
            ):
                raise TrustedTimeGracefulStopV2Rejected(f"{name} must be true")
    if stage is LifecycleV2Stage.NAMED_VOLUMES_PRESERVED and value["volume_delete_call_count"] != 0:
        raise TrustedTimeGracefulStopV2Rejected("volume delete reachability is forbidden")


@dataclass(frozen=True, slots=True)
class LifecycleV2ProgressRecord:
    graceful_stop_operation_id: str
    root_sha256: str
    ordinal: int
    stage: LifecycleV2Stage
    predecessor_sha256: str
    effect_kind: str
    deadline_boottime_ns: int
    evidence: FrozenJsonObject
    recorded_at_utc: str

    def __post_init__(self) -> None:
        _require_identifier(self.graceful_stop_operation_id, "graceful_stop_operation_id")
        _require_sha256(self.root_sha256, "root_sha256")
        _require_int(self.ordinal, "ordinal", minimum=1)
        if self.ordinal >= LIFECYCLE_V2_MAXIMUM_ENTRIES:
            raise TrustedTimeGracefulStopV2Rejected("record ordinal exceeds lifecycle bound")
        if type(self.stage) is not LifecycleV2Stage or self.stage is LifecycleV2Stage.ROOT_RESERVED:
            raise TrustedTimeGracefulStopV2Rejected("progress stage is invalid")
        _require_sha256(self.predecessor_sha256, "predecessor_sha256")
        _require_identifier(self.effect_kind, "effect_kind")
        _require_int(self.deadline_boottime_ns, "deadline_boottime_ns")
        if type(self.evidence) is not FrozenJsonObject:
            raise TrustedTimeGracefulStopV2Rejected("progress evidence is not frozen")
        _validate_evidence(self.stage, self.evidence)
        _require_utc(self.recorded_at_utc, "recorded_at_utc")

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "graceful_stop_lifecycle_v2_progress_retained",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": self.graceful_stop_operation_id,
            "root_sha256": self.root_sha256,
            "ordinal": self.ordinal,
            "stage": self.stage.value,
            "predecessor_sha256": self.predecessor_sha256,
            "effect_kind": self.effect_kind,
            "deadline_boottime_ns": self.deadline_boottime_ns,
            "evidence": self.evidence.to_dict(),
            "recorded_at_utc": self.recorded_at_utc,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_progress_record(encoded: object) -> LifecycleV2ProgressRecord:
    value = decode_canonical_v2_json_object(
        encoded, maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES
    )
    _require_fields(value, _PROGRESS_FIELDS)
    if (
        value["contract_version"] != LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION
        or value["service"] != LIFECYCLE_V2_SERVICE
        or value["status"] != "graceful_stop_lifecycle_v2_progress_retained"
        or value["lifecycle_version"] != 2
    ):
        raise TrustedTimeGracefulStopV2Rejected("record discriminator is not lifecycle v2")
    try:
        stage = LifecycleV2Stage(cast(str, value["stage"]))
    except (TypeError, ValueError) as error:
        raise TrustedTimeGracefulStopV2Rejected("progress stage is unknown") from error
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=value["graceful_stop_operation_id"],  # type: ignore[arg-type]
        root_sha256=value["root_sha256"],  # type: ignore[arg-type]
        ordinal=value["ordinal"],  # type: ignore[arg-type]
        stage=stage,
        predecessor_sha256=value["predecessor_sha256"],  # type: ignore[arg-type]
        effect_kind=value["effect_kind"],  # type: ignore[arg-type]
        deadline_boottime_ns=value["deadline_boottime_ns"],  # type: ignore[arg-type]
        evidence=FrozenJsonObject.capture(value["evidence"]),
        recorded_at_utc=value["recorded_at_utc"],  # type: ignore[arg-type]
    )


def lifecycle_v2_progress_file_name(record: LifecycleV2ProgressRecord) -> str:
    if type(record) is not LifecycleV2ProgressRecord:
        raise TrustedTimeGracefulStopV2Rejected("progress filename requires an exact record")
    return (
        "trusted-time-post-enrollment-graceful-stop-v2-record-"
        f"{record.ordinal:02d}-{record.sha256}.json"
    )


_TRANSCRIPT_ENTRY_FIELDS = frozenset(
    {
        "ordinal",
        "stage",
        "record_artifact_kind",
        "record_contract_version",
        "record_artifact_sha256",
        "predecessor_sha256",
        "wire_artifact_kind",
        "wire_artifact_path",
        "wire_artifact_file_name",
        "wire_artifact_sha256",
    }
)
_TRANSCRIPT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "lifecycle_version",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "last_ordinal",
        "last_stage",
        "entry_count",
        "entries",
    }
)


@dataclass(frozen=True, slots=True)
class LifecycleV2TranscriptEntry:
    ordinal: int
    stage: LifecycleV2Stage
    record_artifact_kind: str
    record_contract_version: str
    record_artifact_sha256: str
    predecessor_sha256: str | None
    wire_artifact_kind: str | None = None
    wire_artifact_path: str | None = None
    wire_artifact_file_name: str | None = None
    wire_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        _require_int(self.ordinal, "ordinal")
        if type(self.stage) is not LifecycleV2Stage:
            raise TrustedTimeGracefulStopV2Rejected("transcript stage is invalid")
        if self.ordinal == 0:
            if (
                self.stage is not LifecycleV2Stage.ROOT_RESERVED
                or self.record_artifact_kind != "root"
                or self.record_contract_version != LIFECYCLE_V2_ROOT_CONTRACT_VERSION
                or self.predecessor_sha256 is not None
            ):
                raise TrustedTimeGracefulStopV2Rejected("transcript root entry is invalid")
        else:
            if (
                self.stage is LifecycleV2Stage.ROOT_RESERVED
                or self.record_artifact_kind != "progress"
                or self.record_contract_version != LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION
                or self.predecessor_sha256 is None
            ):
                raise TrustedTimeGracefulStopV2Rejected("transcript progress entry is invalid")
            _require_sha256(self.predecessor_sha256, "predecessor_sha256")
        _require_sha256(self.record_artifact_sha256, "record_artifact_sha256")
        wire_values = (
            self.wire_artifact_kind,
            self.wire_artifact_path,
            self.wire_artifact_file_name,
            self.wire_artifact_sha256,
        )
        wire_stage = self.stage in {
            LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
        }
        if wire_stage:
            if self.ordinal != 2:
                raise TrustedTimeGracefulStopV2Rejected("terminal wire stage must be ordinal two")
            if any(value is None for value in wire_values):
                raise TrustedTimeGracefulStopV2Rejected(
                    "terminal wire stage must bind its artifact"
                )
            if self.wire_artifact_kind not in {
                "signed_result_envelope",
                "signed_error_envelope",
            }:
                raise TrustedTimeGracefulStopV2Rejected("wire artifact kind is invalid")
            _require_sha256(self.wire_artifact_sha256, "wire_artifact_sha256")
        elif any(value is not None for value in wire_values):
            raise TrustedTimeGracefulStopV2Rejected("only terminal wire stages bind artifacts")

    def to_dict(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "stage": self.stage.value,
            "record_artifact_kind": self.record_artifact_kind,
            "record_contract_version": self.record_contract_version,
            "record_artifact_sha256": self.record_artifact_sha256,
            "predecessor_sha256": self.predecessor_sha256,
            "wire_artifact_kind": self.wire_artifact_kind,
            "wire_artifact_path": self.wire_artifact_path,
            "wire_artifact_file_name": self.wire_artifact_file_name,
            "wire_artifact_sha256": self.wire_artifact_sha256,
        }


@dataclass(frozen=True, slots=True)
class LifecycleV2Transcript:
    environment: str
    graceful_stop_operation_id: str
    root_sha256: str
    entries: tuple[LifecycleV2TranscriptEntry, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.environment, "environment")
        _require_identifier(self.graceful_stop_operation_id, "graceful_stop_operation_id")
        _require_sha256(self.root_sha256, "root_sha256")
        if (
            type(self.entries) is not tuple
            or not self.entries
            or len(self.entries) > LIFECYCLE_V2_MAXIMUM_ENTRIES
        ):
            raise TrustedTimeGracefulStopV2Rejected("transcript entry count is invalid")
        previous_digest: str | None = None
        for ordinal, entry in enumerate(self.entries):
            if type(entry) is not LifecycleV2TranscriptEntry or entry.ordinal != ordinal:
                raise TrustedTimeGracefulStopV2Rejected("transcript ordinals are not gap-free")
            if ordinal == 0:
                if entry.record_artifact_sha256 != self.root_sha256:
                    raise TrustedTimeGracefulStopV2Rejected("transcript root digest disagrees")
            elif entry.predecessor_sha256 != previous_digest:
                raise TrustedTimeGracefulStopV2Rejected("transcript predecessor chain disagrees")
            previous_digest = entry.record_artifact_sha256

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": LIFECYCLE_V2_TRANSCRIPT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "graceful_stop_lifecycle_v2_transcript_retained",
            "lifecycle_version": 2,
            "environment": self.environment,
            "graceful_stop_operation_id": self.graceful_stop_operation_id,
            "root_sha256": self.root_sha256,
            "last_ordinal": self.entries[-1].ordinal,
            "last_stage": self.entries[-1].stage.value,
            "entry_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=LIFECYCLE_V2_TRANSCRIPT_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/lifecycle-transcript/v2",
            self.encoded,
        )

    @property
    def file_name(self) -> str:
        return (
            "trusted-time-post-enrollment-graceful-stop-v2-transcript-"
            f"{self.entries[-1].ordinal:02d}-{self.sha256}.json"
        )


def decode_lifecycle_v2_transcript(encoded: object) -> LifecycleV2Transcript:
    value = decode_canonical_v2_json_object(
        encoded, maximum_bytes=LIFECYCLE_V2_TRANSCRIPT_MAXIMUM_BYTES
    )
    _require_fields(value, _TRANSCRIPT_FIELDS)
    if (
        value["contract_version"] != LIFECYCLE_V2_TRANSCRIPT_CONTRACT_VERSION
        or value["service"] != LIFECYCLE_V2_SERVICE
        or value["status"] != "graceful_stop_lifecycle_v2_transcript_retained"
        or value["lifecycle_version"] != 2
        or type(value["entries"]) is not list
    ):
        raise TrustedTimeGracefulStopV2Rejected("transcript discriminator is invalid")
    entries: list[LifecycleV2TranscriptEntry] = []
    for raw_entry in value["entries"]:
        if type(raw_entry) is not dict:
            raise TrustedTimeGracefulStopV2Rejected("transcript entry must be an object")
        _require_fields(raw_entry, _TRANSCRIPT_ENTRY_FIELDS)
        try:
            stage = LifecycleV2Stage(raw_entry["stage"])
        except (TypeError, ValueError) as error:
            raise TrustedTimeGracefulStopV2Rejected("transcript stage is unknown") from error
        entries.append(
            LifecycleV2TranscriptEntry(
                ordinal=raw_entry["ordinal"],
                stage=stage,
                record_artifact_kind=raw_entry["record_artifact_kind"],
                record_contract_version=raw_entry["record_contract_version"],
                record_artifact_sha256=raw_entry["record_artifact_sha256"],
                predecessor_sha256=raw_entry["predecessor_sha256"],
                wire_artifact_kind=raw_entry["wire_artifact_kind"],
                wire_artifact_path=raw_entry["wire_artifact_path"],
                wire_artifact_file_name=raw_entry["wire_artifact_file_name"],
                wire_artifact_sha256=raw_entry["wire_artifact_sha256"],
            )
        )
    transcript = LifecycleV2Transcript(
        environment=value["environment"],  # type: ignore[arg-type]
        graceful_stop_operation_id=value["graceful_stop_operation_id"],  # type: ignore[arg-type]
        root_sha256=value["root_sha256"],  # type: ignore[arg-type]
        entries=tuple(entries),
    )
    if (
        value["last_ordinal"] != transcript.entries[-1].ordinal
        or value["last_stage"] != transcript.entries[-1].stage.value
        or value["entry_count"] != len(transcript.entries)
    ):
        raise TrustedTimeGracefulStopV2Rejected("transcript summary disagrees with entries")
    return transcript


def lifecycle_v2_dispatch_prefix_sha256(
    root: LifecycleV2Root,
    request_intent: LifecycleV2ProgressRecord,
) -> str:
    if (
        type(root) is not LifecycleV2Root
        or type(request_intent) is not LifecycleV2ProgressRecord
        or request_intent.ordinal != 1
        or request_intent.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
        or request_intent.root_sha256 != root.sha256
        or request_intent.predecessor_sha256 != root.sha256
        or request_intent.graceful_stop_operation_id != root.graceful_stop_operation_id
    ):
        raise TrustedTimeGracefulStopV2Rejected("dispatch prefix inputs are not one exact prefix")
    evidence = request_intent.evidence.to_dict()
    basis = {
        "contract_version": "phase6d-post-enrollment-graceful-stop-lifecycle-dispatch-prefix-v2",
        "service": LIFECYCLE_V2_SERVICE,
        "status": "lifecycle_dispatch_prefix_bound",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "request_basis_sha256": evidence["arguments_sha256"],
        "request_intent_sha256": request_intent.sha256,
        "root_ordinal": 0,
        "root_stage": LifecycleV2Stage.ROOT_RESERVED.value,
        "request_intent_ordinal": 1,
        "request_intent_stage": request_intent.stage.value,
        "request_intent_predecessor_sha256": request_intent.predecessor_sha256,
    }
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/lifecycle-dispatch-prefix/v2",
        canonical_v2_json_bytes(basis, maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES),
    )


_REQUEST_BASIS_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "graceful_stop_decision_v1_sha256",
        "historical_decision_receipt_sha256",
        "graceful_stop_operator_attestation_envelope_sha256",
        "lifecycle_root_sha256",
        "admission_sha256",
        "topology_sha256",
        "topology_lease_sha256",
        "trusted_head_sha256",
        "supervisor_container_id",
        "channel_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "checkpoint_reason",
        "exact_new_record_required",
        "clean_stop_result_deadline_boottime_ns",
        "transport_cleanup_required",
        "transport_cleanup_deadline_boottime_ns",
        "admission_started_boottime_ns",
        "operation_deadline_boottime_ns",
    }
)
_FINAL_REQUEST_FIELDS = _REQUEST_BASIS_FIELDS | {
    "request_basis_sha256",
    "request_intent_sha256",
    "lifecycle_dispatch_prefix_sha256",
}


def _validate_request_common(value: dict[str, object], *, final: bool) -> None:
    _require_fields(value, _FINAL_REQUEST_FIELDS if final else _REQUEST_BASIS_FIELDS)
    expected_contract = (
        LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION
        if final
        else LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION
    )
    expected_status = (
        "operation_bound_clean_stop_requested"
        if final
        else "operation_bound_clean_stop_request_basis_retained"
    )
    if (
        value["contract_version"] != expected_contract
        or value["service"] != LIFECYCLE_V2_CLEAN_STOP_SERVICE
        or value["status"] != expected_status
        or value["checkpoint_reason"] != "clean_stop"
        or value["exact_new_record_required"] is not True
        or value["transport_cleanup_required"] is not True
    ):
        raise TrustedTimeGracefulStopV2Rejected("clean-stop request discriminator is invalid")
    _require_identifier(value["environment"], "environment")
    _require_identifier(value["graceful_stop_operation_id"], "graceful_stop_operation_id")
    for name in value:
        if name.endswith("_sha256"):
            _require_sha256(value[name], name)
    start, operation_deadline = _require_exact_deadline(
        value["admission_started_boottime_ns"], value["operation_deadline_boottime_ns"]
    )
    result_deadline = _require_int(
        value["clean_stop_result_deadline_boottime_ns"],
        "clean_stop_result_deadline_boottime_ns",
    )
    cleanup_deadline = _require_int(
        value["transport_cleanup_deadline_boottime_ns"],
        "transport_cleanup_deadline_boottime_ns",
    )
    if not start < result_deadline < cleanup_deadline <= operation_deadline:
        raise TrustedTimeGracefulStopV2Rejected("request deadlines are not strictly ordered")
    if cleanup_deadline != min(result_deadline + LIFECYCLE_V2_COMMIT_BUDGET_NS, operation_deadline):
        raise TrustedTimeGracefulStopV2Rejected("transport cleanup deadline is not exact")


@dataclass(frozen=True, slots=True)
class LifecycleV2CleanStopRequestBasis:
    fields: FrozenJsonObject

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        _validate_request_common(frozen.to_dict(), final=False)
        return cls(frozen)

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=64 * 1_024)

    @property
    def sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/clean-stop-request-basis/v2",
            self.encoded,
        )


@dataclass(frozen=True, slots=True)
class LifecycleV2CleanStopRequest:
    fields: FrozenJsonObject

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        _validate_request_common(frozen.to_dict(), final=True)
        return cls(frozen)

    @classmethod
    def from_prefix(
        cls,
        basis: LifecycleV2CleanStopRequestBasis,
        *,
        request_intent_sha256: str,
        lifecycle_dispatch_prefix_sha256: str,
    ) -> Self:
        if type(basis) is not LifecycleV2CleanStopRequestBasis:
            raise TrustedTimeGracefulStopV2Rejected("request basis type is invalid")
        _require_sha256(request_intent_sha256, "request_intent_sha256")
        _require_sha256(lifecycle_dispatch_prefix_sha256, "lifecycle_dispatch_prefix_sha256")
        value = basis.to_dict()
        value["contract_version"] = LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION
        value["status"] = "operation_bound_clean_stop_requested"
        value["request_basis_sha256"] = basis.sha256
        value["request_intent_sha256"] = request_intent_sha256
        value["lifecycle_dispatch_prefix_sha256"] = lifecycle_dispatch_prefix_sha256
        return cls.capture(value)

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=64 * 1_024)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_clean_stop_request_basis(
    encoded: object,
) -> LifecycleV2CleanStopRequestBasis:
    return LifecycleV2CleanStopRequestBasis.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=64 * 1_024)
    )


def decode_lifecycle_v2_clean_stop_request(encoded: object) -> LifecycleV2CleanStopRequest:
    return LifecycleV2CleanStopRequest.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=64 * 1_024)
    )


_TRANSPORT_ENVELOPE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "protocol_version",
        "environment",
        "direction",
        "frame_type",
        "payload_contract_version",
        "key_generation",
        "signing_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "message_counter",
        "deadline_boottime_ns",
        "payload_sha256",
        "payload_base64",
        "signature_ed25519_base64",
    }
)
_FRAME_RULES = {
    "clean_stop_request": (
        "host_to_supervisor",
        2,
        LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
        65_536,
    ),
    "clean_stop_result": (
        "supervisor_to_host",
        1,
        "phase6d-trusted-time-head-anchor-clean-stop-result-v2",
        180_224,
    ),
    "clean_stop_error": (
        "supervisor_to_host",
        1,
        "phase6d-trusted-time-head-anchor-clean-stop-error-v2",
        32_768,
    ),
}


def _canonical_base64(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise TrustedTimeGracefulStopV2Rejected("base64 field is not canonical ASCII")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TrustedTimeGracefulStopV2Rejected("base64 field is malformed") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise TrustedTimeGracefulStopV2Rejected("base64 field has an alternate encoding")
    if exact_length is not None and len(decoded) != exact_length:
        raise TrustedTimeGracefulStopV2Rejected("base64 field has the wrong decoded length")
    return decoded


@dataclass(frozen=True, slots=True)
class UnverifiedLifecycleV2TransportEnvelope:
    """Structurally exact signed bytes; cryptographic authentication is separate."""

    fields: FrozenJsonObject
    payload: bytes
    signature: bytes

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _TRANSPORT_ENVELOPE_FIELDS)
        if (
            fields["contract_version"] != LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_TRANSPORT_SERVICE
            or fields["protocol_version"] != 2
            or fields["frame_type"] not in _FRAME_RULES
        ):
            raise TrustedTimeGracefulStopV2Rejected("transport envelope discriminator is invalid")
        frame_type = fields["frame_type"]
        direction, counter, payload_contract, payload_limit = _FRAME_RULES[frame_type]
        if (
            fields["direction"] != direction
            or fields["message_counter"] != counter
            or fields["payload_contract_version"] != payload_contract
        ):
            raise TrustedTimeGracefulStopV2Rejected("transport frame role or counter is invalid")
        _require_identifier(fields["environment"], "environment")
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        _require_identifier(fields["signing_key_id"], "signing_key_id")
        for name in (
            "boot_epoch_sha256",
            "host_process_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "channel_id",
            "lifecycle_dispatch_prefix_sha256",
            "payload_sha256",
        ):
            _require_sha256(fields[name], name)
        _require_int(fields["deadline_boottime_ns"], "deadline_boottime_ns")
        payload = _canonical_base64(fields["payload_base64"])
        signature = _canonical_base64(fields["signature_ed25519_base64"], exact_length=64)
        if len(payload) > payload_limit or _sha256(payload) != fields["payload_sha256"]:
            raise TrustedTimeGracefulStopV2Rejected("transport payload bound or digest disagrees")
        payload_value = decode_canonical_v2_json_object(payload, maximum_bytes=payload_limit)
        if payload_value.get("contract_version") != payload_contract:
            raise TrustedTimeGracefulStopV2Rejected("transport payload contract disagrees")
        result = cls(fields=frozen, payload=payload, signature=signature)
        if len(result.encoded) > LIFECYCLE_V2_WIRE_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("signed envelope exceeds seqpacket bound")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)

    @property
    def frame_type(self) -> str:
        return self.to_dict()["frame_type"]  # type: ignore[return-value]

    @property
    def signature_sha256(self) -> str:
        return _sha256(self.signature)


@dataclass(frozen=True, slots=True, eq=False)
class _FakeAuthenticatedLifecycleV2TransportEnvelope:
    """Test-only authentication receipt; no production verifier can construct it."""

    envelope: UnverifiedLifecycleV2TransportEnvelope
    _capability: object


def _authenticate_lifecycle_v2_transport_envelope_for_fake(
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    *,
    capability: object,
) -> _FakeAuthenticatedLifecycleV2TransportEnvelope:
    if (
        type(envelope) is not UnverifiedLifecycleV2TransportEnvelope
        or capability is not _FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY
    ):
        raise TrustedTimeGracefulStopV2Rejected("fake transport authentication is invalid")
    return _FakeAuthenticatedLifecycleV2TransportEnvelope(envelope, capability)


def _require_fake_authenticated_lifecycle_v2_transport_envelope(
    value: object,
) -> UnverifiedLifecycleV2TransportEnvelope:
    if (
        type(value) is not _FakeAuthenticatedLifecycleV2TransportEnvelope
        or value._capability is not _FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY
        or type(value.envelope) is not UnverifiedLifecycleV2TransportEnvelope
    ):
        raise TrustedTimeGracefulStopV2Rejected("terminal wire is not fake-authenticated")
    return value.envelope


def decode_unverified_lifecycle_v2_transport_envelope(
    encoded: object,
) -> UnverifiedLifecycleV2TransportEnvelope:
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES)
    )


def lifecycle_v2_wire_file_name(envelope: UnverifiedLifecycleV2TransportEnvelope) -> str:
    if type(envelope) is not UnverifiedLifecycleV2TransportEnvelope:
        raise TrustedTimeGracefulStopV2Rejected("wire filename requires an exact envelope")
    if envelope.frame_type == "clean_stop_result":
        kind = "result"
    elif envelope.frame_type == "clean_stop_error":
        kind = "error"
    else:
        raise TrustedTimeGracefulStopV2Rejected("request envelopes are not retained as wire files")
    return f"trusted-time-post-enrollment-graceful-stop-v2-wire-{kind}-{envelope.sha256}.json"


_OUTCOME_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "lifecycle_version",
        "graceful_stop_operation_id",
        "root_sha256",
        "ordinal",
        "predecessor_sha256",
        "final_stage",
        "transcript_sha256",
        "reason_code",
        "pre_effect_binding_sha256",
        "post_teardown_binding_sha256",
        "volume_proof_sha256",
        "terminal_cleanup_sha256",
        "stop_effects_confirmed",
        "teardown_confirmed",
        "terminal_cleanup_confirmed",
        "admission_started_boottime_ns",
        "operation_deadline_boottime_ns",
        "commit_protocol_started_boottime_ns",
        "commit_publication_authorization_deadline_boottime_ns",
        "commit_authorized_boottime_ns",
        "created_at_utc",
    }
)
_COMMIT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "lifecycle_version",
        "graceful_stop_operation_id",
        "root_sha256",
        "outcome_sha256",
        "outcome_status",
        "transcript_sha256",
        "admission_started_boottime_ns",
        "commit_protocol_started_boottime_ns",
        "commit_publication_authorization_deadline_boottime_ns",
        "commit_authorized_boottime_ns",
        "operation_deadline_boottime_ns",
        "committed_at_utc",
    }
)


@dataclass(frozen=True, slots=True)
class LifecycleV2Outcome:
    fields: FrozenJsonObject

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _OUTCOME_FIELDS)
        if (
            fields["contract_version"] != LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["lifecycle_version"] != 2
            or fields["status"] not in {"confirmed_success", "recovery_required"}
        ):
            raise TrustedTimeGracefulStopV2Rejected("outcome discriminator is invalid")
        _require_identifier(fields["graceful_stop_operation_id"], "graceful_stop_operation_id")
        for name in (
            "root_sha256",
            "predecessor_sha256",
            "transcript_sha256",
        ):
            _require_sha256(fields[name], name)
        ordinal = _require_int(fields["ordinal"], "ordinal", minimum=1)
        start, operation_deadline = _require_exact_deadline(
            fields["admission_started_boottime_ns"], fields["operation_deadline_boottime_ns"]
        )
        protocol_start = _require_int(
            fields["commit_protocol_started_boottime_ns"],
            "commit_protocol_started_boottime_ns",
        )
        authorization_deadline = _require_int(
            fields["commit_publication_authorization_deadline_boottime_ns"],
            "commit_publication_authorization_deadline_boottime_ns",
        )
        if protocol_start > MAXIMUM_SIGNED_INTEGER - LIFECYCLE_V2_COMMIT_BUDGET_NS:
            raise TrustedTimeGracefulStopV2Rejected("outcome commit deadline overflows")
        if fields["status"] == "confirmed_success":
            if (
                ordinal != 23
                or fields["final_stage"] != LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED.value
                or fields["reason_code"] != "completed"
                or fields["commit_authorized_boottime_ns"] is not None
                or any(
                    fields[name] is not True
                    for name in (
                        "stop_effects_confirmed",
                        "teardown_confirmed",
                        "terminal_cleanup_confirmed",
                    )
                )
            ):
                raise TrustedTimeGracefulStopV2Rejected("confirmed-success outcome is incomplete")
            for name in (
                "pre_effect_binding_sha256",
                "post_teardown_binding_sha256",
                "volume_proof_sha256",
                "terminal_cleanup_sha256",
            ):
                _require_sha256(fields[name], name)
            expected_deadline = min(
                protocol_start + LIFECYCLE_V2_COMMIT_BUDGET_NS,
                operation_deadline,
            )
        else:
            if any(
                fields[name] is not False
                for name in (
                    "stop_effects_confirmed",
                    "teardown_confirmed",
                    "terminal_cleanup_confirmed",
                )
            ):
                raise TrustedTimeGracefulStopV2Rejected("recovery outcome cannot confirm effects")
            authorized = _require_int(
                fields["commit_authorized_boottime_ns"], "commit_authorized_boottime_ns"
            )
            expected_deadline = protocol_start + LIFECYCLE_V2_COMMIT_BUDGET_NS
            if not protocol_start <= authorized < expected_deadline:
                raise TrustedTimeGracefulStopV2Rejected("recovery outcome authorization expired")
            for name in (
                "pre_effect_binding_sha256",
                "post_teardown_binding_sha256",
                "volume_proof_sha256",
                "terminal_cleanup_sha256",
            ):
                if fields[name] is not None:
                    _require_sha256(fields[name], name)
        if authorization_deadline != expected_deadline:
            raise TrustedTimeGracefulStopV2Rejected("outcome commit deadline is not exact")
        if protocol_start < start:
            raise TrustedTimeGracefulStopV2Rejected("outcome commit predates admission")
        _require_utc(fields["created_at_utc"], "created_at_utc")
        return cls(frozen)

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=LIFECYCLE_V2_OUTCOME_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)

    @property
    def status(self) -> str:
        return self.to_dict()["status"]  # type: ignore[return-value]

    @property
    def file_name(self) -> str:
        return f"trusted-time-post-enrollment-graceful-stop-v2-outcome-{self.sha256}.json"


def decode_lifecycle_v2_outcome(encoded: object) -> LifecycleV2Outcome:
    return LifecycleV2Outcome.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=LIFECYCLE_V2_OUTCOME_MAXIMUM_BYTES)
    )


@dataclass(frozen=True, slots=True)
class LifecycleV2OutcomeCommit:
    fields: FrozenJsonObject

    @classmethod
    def capture(cls, value: object, *, outcome: LifecycleV2Outcome | None = None) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _COMMIT_FIELDS)
        if (
            fields["contract_version"] != LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["status"] != "terminal_outcome_committed"
            or fields["lifecycle_version"] != 2
            or fields["outcome_status"] not in {"confirmed_success", "recovery_required"}
        ):
            raise TrustedTimeGracefulStopV2Rejected("commit discriminator is invalid")
        _require_identifier(fields["graceful_stop_operation_id"], "graceful_stop_operation_id")
        for name in ("root_sha256", "outcome_sha256", "transcript_sha256"):
            _require_sha256(fields[name], name)
        _, operation_deadline = _require_exact_deadline(
            fields["admission_started_boottime_ns"], fields["operation_deadline_boottime_ns"]
        )
        protocol_start = _require_int(
            fields["commit_protocol_started_boottime_ns"],
            "commit_protocol_started_boottime_ns",
        )
        deadline = _require_int(
            fields["commit_publication_authorization_deadline_boottime_ns"],
            "commit_publication_authorization_deadline_boottime_ns",
        )
        authorized = _require_int(
            fields["commit_authorized_boottime_ns"], "commit_authorized_boottime_ns"
        )
        expected_deadline = protocol_start + LIFECYCLE_V2_COMMIT_BUDGET_NS
        if fields["outcome_status"] == "confirmed_success":
            expected_deadline = min(expected_deadline, operation_deadline)
            if authorized >= operation_deadline:
                raise TrustedTimeGracefulStopV2Rejected("success authorization reached cutoff")
        if deadline != expected_deadline or not protocol_start <= authorized < deadline:
            raise TrustedTimeGracefulStopV2Rejected("commit authorization window is invalid")
        _require_utc(fields["committed_at_utc"], "committed_at_utc")
        if outcome is not None:
            if type(outcome) is not LifecycleV2Outcome:
                raise TrustedTimeGracefulStopV2Rejected("commit outcome is not exact")
            outcome_fields = outcome.to_dict()
            for commit_name, outcome_name in (
                ("graceful_stop_operation_id", "graceful_stop_operation_id"),
                ("root_sha256", "root_sha256"),
                ("outcome_status", "status"),
                ("transcript_sha256", "transcript_sha256"),
                ("admission_started_boottime_ns", "admission_started_boottime_ns"),
                ("commit_protocol_started_boottime_ns", "commit_protocol_started_boottime_ns"),
                (
                    "commit_publication_authorization_deadline_boottime_ns",
                    "commit_publication_authorization_deadline_boottime_ns",
                ),
                ("operation_deadline_boottime_ns", "operation_deadline_boottime_ns"),
            ):
                if fields[commit_name] != outcome_fields[outcome_name]:
                    raise TrustedTimeGracefulStopV2Rejected("commit does not bind its outcome")
            outcome_authorized = outcome_fields["commit_authorized_boottime_ns"]
            if outcome.status == "recovery_required" and authorized != outcome_authorized:
                raise TrustedTimeGracefulStopV2Rejected("recovery commit changed authorization")
            if fields["outcome_sha256"] != outcome.sha256:
                raise TrustedTimeGracefulStopV2Rejected("commit outcome digest disagrees")
        return cls(frozen)

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=64 * 1_024)


def decode_lifecycle_v2_outcome_commit(
    encoded: object,
    *,
    outcome: LifecycleV2Outcome | None = None,
) -> LifecycleV2OutcomeCommit:
    return LifecycleV2OutcomeCommit.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=64 * 1_024),
        outcome=outcome,
    )


def lifecycle_v2_non_authority_facts() -> dict[str, bool]:
    """Return the machine-checkable zero-authority surface for this partial slice."""

    return {
        "production_caller_present": False,
        "real_artifact_root_reachable": False,
        "real_transport_reachable": False,
        "real_docker_reachable": False,
        "stop_effect_authorized": False,
        "recovery_effect_authorized": False,
        "trusted_time_stop_enabled": False,
    }


__all__ = [
    "LIFECYCLE_ROOT_FILE_NAME",
    "LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION",
    "LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION",
    "LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME",
    "LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION",
    "LIFECYCLE_V2_ROOT_CONTRACT_VERSION",
    "LIFECYCLE_V2_TRANSCRIPT_CONTRACT_VERSION",
    "LifecycleV2CleanStopRequest",
    "LifecycleV2CleanStopRequestBasis",
    "LifecycleV2Outcome",
    "LifecycleV2OutcomeCommit",
    "LifecycleV2ProgressRecord",
    "LifecycleV2Root",
    "LifecycleV2Stage",
    "LifecycleV2Transcript",
    "LifecycleV2TranscriptEntry",
    "TrustedTimeGracefulStopV2Rejected",
    "UnverifiedLifecycleV2TransportEnvelope",
    "decode_lifecycle_v2_clean_stop_request",
    "decode_lifecycle_v2_clean_stop_request_basis",
    "decode_lifecycle_v2_outcome",
    "decode_lifecycle_v2_outcome_commit",
    "decode_lifecycle_v2_progress_record",
    "decode_lifecycle_v2_root",
    "decode_lifecycle_v2_transcript",
    "decode_unverified_lifecycle_v2_transport_envelope",
    "lifecycle_v2_dispatch_prefix_sha256",
    "lifecycle_v2_non_authority_facts",
    "lifecycle_v2_progress_file_name",
    "lifecycle_v2_wire_file_name",
]
