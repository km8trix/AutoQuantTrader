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
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Never, Self, cast

from packages.domain.trusted_time_graceful_stop_v2_runtime_seal import (
    LifecycleV2RuntimeSealRegistry,
)

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
    try:
        parsed = int(value)
    except (ValueError, OverflowError):
        raise TrustedTimeGracefulStopV2Rejected(
            "JSON integer is outside signed 64-bit bounds"
        ) from None
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
            # A terminal result payload may be 180,224 bytes and its canonical
            # base64 envelope field is therefore larger than 64 KiB.  The
            # surrounding artifact limit remains the allocation boundary.
            if type(node) is str and len(node.encode("utf-8")) > LIFECYCLE_V2_WIRE_MAXIMUM_BYTES:
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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
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


@dataclass(frozen=True, slots=True, init=False)
class FrozenJsonObject:
    """An immutable, canonically sorted nested JSON object."""

    entries: tuple[tuple[str, object], ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("frozen JSON objects require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        if type(value) is not dict:
            raise TrustedTimeGracefulStopV2Rejected("evidence must be one exact JSON object")
        _bounded_tree(value)
        entries = tuple(
            (key, _freeze_json(item))
            for key, item in sorted(value.items(), key=lambda pair: pair[0])
        )
        result = object.__new__(cls)
        object.__setattr__(result, "entries", entries)
        return result

    def to_dict(self) -> dict[str, object]:
        try:
            if type(self.entries) is not tuple:
                raise TrustedTimeGracefulStopV2Rejected(
                    "frozen JSON entries are not canonically represented"
                )
            value = {key: _thaw_json(item) for key, item in self.entries}
            if len(value) != len(self.entries):
                raise TrustedTimeGracefulStopV2Rejected(
                    "frozen JSON entries are not canonically represented"
                )
            if FrozenJsonObject.capture(value).entries != self.entries:
                raise TrustedTimeGracefulStopV2Rejected(
                    "frozen JSON entries are not canonically represented"
                )
            return value
        except TrustedTimeGracefulStopV2Rejected:
            raise
        except (AttributeError, TypeError, ValueError, RecursionError) as error:
            raise TrustedTimeGracefulStopV2Rejected(
                "frozen JSON entries are not canonically represented"
            ) from error


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
        "channel_id",
        "intent_semantic_sha256",
        "binding_evidence",
    }
)

_ADR0109_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
)
_ADR0109_REAUTHENTICATION_STATUS = (
    "provider_terminal_observed_under_stable_sql_authenticated"
)
_ADR0109_OBSERVATION_BUDGET_NS = 120_000_000_000
_REAUTHENTICATION_SEMANTIC_SERVICE = "trusted-time-graceful-stop-lifecycle-v2"
_ADR0109_OBSERVATION_FIELDS = frozenset(
    {
        "contract_version",
        "status",
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_transition_count",
        "confirmed_anchor_local_transition_ordinal",
        "remote_object_count",
        "predecessor_anchor_sha256",
        "current_host_head_sha256",
        "current_anchor_sha256",
        "current_anchor_semantic_sha256",
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "receipt_semantic_sha256",
        "receipt_observed_at_utc",
        "remote_observation_sha256",
        "anchor_authority_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "source_authority_sha256",
        "signing_public_key_sha256",
        "host_identity_sha256",
        "principal_identity_sha256",
        "bucket_identity_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "deadline_monotonic_ns",
        "issuer_binding_sha256",
        "read_only_configuration_sha256",
        "semantic_sha256",
    }
)
_ADR0109_PROVIDER_IDENTITY_FIELDS = (
    "anchor_authority_sha256",
    "deployment_identity_sha256",
    "runtime_database_identity_sha256",
    "anchor_project_identity_sha256",
    "source_authority_sha256",
    "signing_public_key_sha256",
    "host_identity_sha256",
    "principal_identity_sha256",
    "bucket_identity_sha256",
    "read_only_configuration_sha256",
)
_PRE_EFFECT_REAUTHENTICATION_BINDING_EVIDENCE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "clean_stop_request_sha256",
        "clean_stop_result_sha256",
        "channel_id",
        "expected_checkpoint_reason",
        "expected_clean_stop_head_sha256",
        "expected_clean_stop_terminal_result_semantic_sha256",
        "topology_sha256",
        "topology_lease_sha256",
        "transport_quiescence_record_sha256",
        "pre_effect_intent_sha256",
        "adr0109_observation",
        "adr0109_observation_sha256",
        "provider_identity_sha256",
        "observation_semantic_sha256",
        "adr0109_issuer_binding_sha256",
        "adr0109_read_only_configuration_sha256",
        "issuer_challenge_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "observation_deadline_monotonic_ns",
    }
)
_POST_TEARDOWN_REAUTHENTICATION_BINDING_EVIDENCE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "published_prefix_through_ordinal_18_sha256",
        "expected_checkpoint_reason",
        "expected_clean_stop_head_sha256",
        "expected_clean_stop_terminal_result_semantic_sha256",
        "pre_effect_binding_sha256",
        "supervisor_stop_result_sha256",
        "source_stop_result_sha256",
        "supervisor_remove_result_sha256",
        "source_remove_result_sha256",
        "project_network_remove_result_sha256",
        "volume_proof_sha256",
        "post_teardown_intent_sha256",
        "adr0109_observation",
        "adr0109_observation_sha256",
        "provider_identity_sha256",
        "observation_semantic_sha256",
        "adr0109_issuer_binding_sha256",
        "adr0109_read_only_configuration_sha256",
        "issuer_challenge_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "observation_deadline_monotonic_ns",
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
_DOCKER_MUTATION_SEMANTIC_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "result_kind",
        "target_kind",
        "target_id",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
        "primary_request_semantic_sha256",
        "primary_connection_identity",
        "primary_connection_identity_sha256",
        "primary_exchange",
        "primary_exchange_sha256",
        "post_inspect_request_semantic_sha256",
        "post_inspect_connection_identity",
        "post_inspect_connection_identity_sha256",
        "post_inspect_exchange",
        "post_inspect_exchange_sha256",
        "ordered_connection_identity_sha256_list",
        "ordered_trace_entry_list",
        "ordered_trace_entry_sha256_list",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "outcome",
    }
)
_DOCKER_VOLUME_SEMANTIC_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "result_kind",
        "target_kind",
        "target_names",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
        "admission_volume_projection_sha256_list",
        "ordered_request_semantic_sha256_list",
        "ordered_connection_identity_list",
        "ordered_connection_identity_sha256_list",
        "ordered_http_exchange_list",
        "ordered_http_exchange_sha256_list",
        "ordered_trace_entry_list",
        "ordered_trace_entry_sha256_list",
        "post_volume_projection_sha256_list",
        "volume_delete_call_count",
        "proof_started_boottime_ns",
        "proof_completed_boottime_ns",
        "outcome",
    }
)
_DOCKER_CONNECTION_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "channel_id",
        "api_version",
        "connection_ordinal",
        "docker_socket_path",
        "socket_mount_id",
        "socket_mount_parent_id",
        "socket_mount_major_minor",
        "socket_mount_root",
        "socket_mount_point",
        "socket_mount_filesystem_type",
        "socket_mount_source",
        "socket_mount_options",
        "socket_mount_super_options",
        "socket_path_device",
        "socket_path_inode",
        "socket_path_uid",
        "socket_path_gid",
        "socket_path_mode",
        "peer_uid",
        "peer_gid",
        "peer_pid",
        "daemon_start_time_ticks",
        "daemon_proc_device",
        "daemon_proc_inode",
        "daemon_pid_namespace_inode",
        "daemon_executable_device",
        "daemon_executable_inode",
        "daemon_executable_size",
        "daemon_executable_uid",
        "daemon_executable_gid",
        "daemon_executable_mode",
        "daemon_executable_nlink",
        "daemon_executable_sha256",
        "daemon_cgroup_sha256",
        "local_socket_device",
        "local_socket_inode",
        "local_socket_cookie",
        "admitted_daemon_info_projection_sha256",
        "path_preconnect_validated_boottime_ns",
        "opened_boottime_ns",
        "pre_request_revalidated_boottime_ns",
        "response_headers_revalidated_boottime_ns",
        "response_complete_revalidated_boottime_ns",
        "call_deadline_boottime_ns",
    }
)
_DOCKER_EXCHANGE_FIELDS = frozenset(
    {
        "exchange_kind",
        "target_kind",
        "target_identity",
        "request_semantic_sha256",
        "connection_identity_sha256",
        "http_status",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "trace_entry_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
    }
)
_DOCKER_TRACE_FIELDS = frozenset(
    {
        "trace_ordinal",
        "request_semantic_sha256",
        "http_status",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "connection_identity_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
        "previous_trace_entry_sha256",
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
_WIRE_PUBLICATION_RECEIPT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "artifact_kind",
        "artifact_directory_path",
        "artifact_directory_device",
        "artifact_directory_inode",
        "artifact_path",
        "file_name",
        "file_device",
        "file_inode",
        "file_mode",
        "file_size",
        "signed_envelope_sha256",
        "envelope_contract_version",
        "frame_type",
        "payload_contract_version",
        "payload_sha256",
        "signature_sha256",
        "key_generation",
        "signing_key_id",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "message_counter",
        "deadline_boottime_ns",
        "directory_fsync_completed",
        "stable_readback_completed",
        "publication_authorized_boottime_ns",
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
        "socket_absence",
        "credential_path_absence",
        "empty_mount_projection",
        "unmount_receipt",
        "native_owner_cleanup_receipt",
        "all_private_material_unreachable",
        "cleanup_completed_boottime_ns",
    }
)
_TERMINAL_PATH_ABSENCE_FIELDS = frozenset(
    {
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "absence_kind",
        "paths",
        "all_absent",
        "observed_boottime_ns",
    }
)
_TERMINAL_EMPTY_MOUNT_PROJECTION_FIELDS = frozenset(
    {
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "mounts",
    }
)
_TERMINAL_EMPTY_MOUNT_IDENTITY_FIELDS = frozenset(
    {
        "path",
        "mount_id",
        "mount_parent_id",
        "mount_major_minor",
        "mount_root",
        "mount_options",
        "directory_device",
        "directory_inode",
        "directory_uid",
        "directory_gid",
        "directory_mode",
        "entry_count",
    }
)
_TERMINAL_UNMOUNT_RECEIPT_FIELDS = frozenset(
    {
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "mounts",
    }
)
_TERMINAL_UNMOUNT_ENTRY_FIELDS = frozenset(
    {"mount_id", "unmounted", "mount_absent", "completed_boottime_ns"}
)
_TERMINAL_NATIVE_OWNER_CLEANUP_RECEIPT_FIELDS = frozenset(
    {
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "channel_id",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "native_owner_set_sha256",
        "owner_count_before",
        "owner_count_after",
        "every_owner_invalidated",
        "every_private_buffer_zeroized_or_process_destroyed",
        "completed_boottime_ns",
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
_DOCKER_RESULT_RULE_BY_STAGE: dict[
    LifecycleV2Stage,
    tuple[str, str, str, str, str, int, int],
] = {
    LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED: (
        "phase6d-trusted-time-graceful-stop-docker-container-stop-result-v2",
        "container_stop_confirmed",
        "container_stop",
        "container",
        "stopped",
        6,
        200,
    ),
    LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED: (
        "phase6d-trusted-time-graceful-stop-docker-container-stop-result-v2",
        "container_stop_confirmed",
        "container_stop",
        "container",
        "stopped",
        8,
        200,
    ),
    LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED: (
        "phase6d-trusted-time-graceful-stop-docker-container-remove-result-v2",
        "container_removal_confirmed",
        "container_remove",
        "container",
        "absent",
        10,
        404,
    ),
    LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED: (
        "phase6d-trusted-time-graceful-stop-docker-container-remove-result-v2",
        "container_removal_confirmed",
        "container_remove",
        "container",
        "absent",
        12,
        404,
    ),
    LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED: (
        "phase6d-trusted-time-graceful-stop-docker-network-remove-result-v2",
        "network_removal_confirmed",
        "network_remove",
        "network",
        "absent",
        14,
        404,
    ),
}


def _capture_lifecycle_v2_reauthentication_binding_evidence(
    value: object,
    *,
    boundary: str,
) -> tuple[FrozenJsonObject, str]:
    """Canonicalize and independently authenticate retained ADR-0109 primitives."""

    if boundary == "pre_effect":
        expected_fields = _PRE_EFFECT_REAUTHENTICATION_BINDING_EVIDENCE_FIELDS
        expected_status = "fresh_pre_effect_adr0109_observation_bound"
    elif boundary == "post_teardown":
        expected_fields = _POST_TEARDOWN_REAUTHENTICATION_BINDING_EVIDENCE_FIELDS
        expected_status = "distinct_post_teardown_adr0109_observation_bound"
    else:
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication binding evidence boundary is outside the closed set"
        )
    frozen = FrozenJsonObject.capture(
        value.to_dict() if type(value) is FrozenJsonObject else value
    )
    fields = frozen.to_dict()
    _require_fields(fields, expected_fields)
    expected_contract = (
        "phase6d-trusted-time-graceful-stop-"
        f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
    )
    if (
        fields["contract_version"] != expected_contract
        or fields["service"] != LIFECYCLE_V2_SERVICE
        or fields["status"] != expected_status
        or fields["expected_checkpoint_reason"] != "clean_stop"
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication binding evidence discriminator is invalid"
        )
    _require_identifier(fields["environment"], "environment")
    _require_identifier(
        fields["graceful_stop_operation_id"],
        "graceful_stop_operation_id",
    )
    for name, item in fields.items():
        if name.endswith("_sha256"):
            _require_sha256(item, name)

    raw_observation = fields["adr0109_observation"]
    if type(raw_observation) is not dict:
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation must be one exact object"
        )
    observation = FrozenJsonObject.capture(raw_observation)
    observation_fields = observation.to_dict()
    _require_fields(observation_fields, _ADR0109_OBSERVATION_FIELDS)
    if (
        observation_fields["contract_version"]
        != _ADR0109_REAUTHENTICATION_CONTRACT_VERSION
        or observation_fields["status"] != _ADR0109_REAUTHENTICATION_STATUS
        or observation_fields["checkpoint_reason"] != "clean_stop"
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation discriminator is invalid"
        )
    anchor_sequence = _require_int(
        observation_fields["anchor_sequence"],
        "anchor_sequence",
        minimum=3,
    )
    confirmed_anchor_count = _require_int(
        observation_fields["confirmed_anchor_count"],
        "confirmed_anchor_count",
        minimum=3,
    )
    remote_object_count = _require_int(
        observation_fields["remote_object_count"],
        "remote_object_count",
        minimum=3,
    )
    local_transition_count = _require_int(
        observation_fields["local_transition_count"],
        "local_transition_count",
        minimum=3,
    )
    confirmed_local_ordinal = _require_int(
        observation_fields["confirmed_anchor_local_transition_ordinal"],
        "confirmed_anchor_local_transition_ordinal",
        minimum=3,
    )
    if (
        confirmed_anchor_count != anchor_sequence
        or remote_object_count != anchor_sequence
        or confirmed_local_ordinal != local_transition_count
        or local_transition_count < anchor_sequence
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation counts are inconsistent"
        )
    for name, item in observation_fields.items():
        if name.endswith("_sha256"):
            _require_sha256(item, name)
    semantic_payload = dict(observation_fields)
    observation_semantic_sha256 = cast(
        str,
        semantic_payload.pop("semantic_sha256"),
    )
    if (
        _sha256(
            canonical_v2_json_bytes(
                semantic_payload,
                maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
            )
        )
        != observation_semantic_sha256
        or observation_fields["candidate_remote_readback_sha256"]
        != observation_fields["current_anchor_sha256"]
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation semantic binding is not canonical"
        )
    _require_utc(
        observation_fields["receipt_observed_at_utc"],
        "receipt_observed_at_utc",
    )
    observation_started = _require_int(
        observation_fields["observation_started_monotonic_ns"],
        "observation_started_monotonic_ns",
    )
    observation_completed = _require_int(
        observation_fields["observation_completed_monotonic_ns"],
        "observation_completed_monotonic_ns",
    )
    observation_deadline = _require_int(
        observation_fields["deadline_monotonic_ns"],
        "deadline_monotonic_ns",
    )
    if (
        observation_started
        > MAXIMUM_SIGNED_INTEGER - _ADR0109_OBSERVATION_BUDGET_NS
        or observation_deadline
        != observation_started + _ADR0109_OBSERVATION_BUDGET_NS
        or not observation_started <= observation_completed < observation_deadline
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation interval is not the exact 120-second interval"
        )
    provider_projection = {
        name: observation_fields[name] for name in _ADR0109_PROVIDER_IDENTITY_FIELDS
    }
    provider_identity_sha256 = _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/adr0109-provider-identity/v2",
        canonical_v2_json_bytes(
            provider_projection,
            maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
        ),
    )
    observation_encoded = canonical_v2_json_bytes(
        observation_fields,
        maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
    )
    binding_started = _require_int(
        fields["observation_started_monotonic_ns"],
        "observation_started_monotonic_ns",
    )
    binding_completed = _require_int(
        fields["observation_completed_monotonic_ns"],
        "observation_completed_monotonic_ns",
    )
    binding_deadline = _require_int(
        fields["observation_deadline_monotonic_ns"],
        "observation_deadline_monotonic_ns",
    )
    if (
        fields["expected_clean_stop_head_sha256"]
        != observation_fields["current_anchor_sha256"]
        or fields["adr0109_observation_sha256"] != _sha256(observation_encoded)
        or fields["provider_identity_sha256"] != provider_identity_sha256
        or fields["observation_semantic_sha256"] != observation_semantic_sha256
        or fields["adr0109_issuer_binding_sha256"]
        != observation_fields["issuer_binding_sha256"]
        or fields["adr0109_read_only_configuration_sha256"]
        != observation_fields["read_only_configuration_sha256"]
        or binding_started != observation_started
        or binding_completed != observation_completed
        or binding_deadline != observation_deadline
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication binding did not retain its exact ADR-0109 primitives"
        )
    binding_evidence_sha256 = _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/"
        f"{boundary.replace('_', '-')}-reauthentication-binding/v2",
        canonical_v2_json_bytes(
            fields,
            maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
        ),
    )
    return frozen, binding_evidence_sha256


def _validate_reauthentication_result_evidence(
    stage: LifecycleV2Stage,
    value: dict[str, object],
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
) -> None:
    boundary = (
        "pre_effect"
        if stage is LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND
        else "post_teardown"
    )
    binding_evidence, binding_evidence_sha256 = (
        _capture_lifecycle_v2_reauthentication_binding_evidence(
            value["binding_evidence"],
            boundary=boundary,
        )
    )
    binding_fields = binding_evidence.to_dict()
    _require_sha256(value["channel_id"], "channel_id")
    if (
        binding_fields["graceful_stop_operation_id"]
        != graceful_stop_operation_id
        or binding_fields["lifecycle_root_sha256"] != root_sha256
        or value["disposition"] != f"{boundary}_reauthentication_bound"
        or value["responder_identity_sha256"]
        != binding_fields["adr0109_issuer_binding_sha256"]
        or value["observation_semantic_sha256"]
        != binding_fields["observation_semantic_sha256"]
        or value["observed_head_sha256"]
        != binding_fields["expected_clean_stop_head_sha256"]
        or value["provider_identity_sha256"]
        != binding_fields["provider_identity_sha256"]
        or value["call_started_boottime_ns"]
        != binding_fields["observation_started_monotonic_ns"]
        or value["call_completed_boottime_ns"]
        != binding_fields["observation_completed_monotonic_ns"]
        or value["binding_semantic_sha256"] != value["result_semantic_sha256"]
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication result crossed its exact primitive binding evidence"
        )
    semantic_payload = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-"
            f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
        ),
        "service": _REAUTHENTICATION_SEMANTIC_SERVICE,
        "status": f"{boundary}_reauthentication_bound",
        "environment": binding_fields["environment"],
        "graceful_stop_operation_id": graceful_stop_operation_id,
        "lifecycle_root_sha256": root_sha256,
        "channel_id": value["channel_id"],
        "boundary": boundary,
        "intent_semantic_sha256": value["intent_semantic_sha256"],
        "binding_evidence_sha256": binding_evidence_sha256,
        "issuer_identity_sha256": value["responder_identity_sha256"],
        "challenge_sha256": binding_fields["issuer_challenge_sha256"],
        "observation_semantic_sha256": value["observation_semantic_sha256"],
        "observed_head_sha256": value["observed_head_sha256"],
        "provider_identity_sha256": value["provider_identity_sha256"],
        "observation_started_boottime_ns": value["call_started_boottime_ns"],
        "observation_completed_boottime_ns": value["call_completed_boottime_ns"],
    }
    semantic_sha256 = _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/"
        f"{boundary.replace('_', '-')}-reauthentication-binding/v2",
        canonical_v2_json_bytes(
            semantic_payload,
            maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
        ),
    )
    if (
        value["binding_semantic_sha256"] != semantic_sha256
        or value["result_semantic_sha256"] != semantic_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication semantic digest did not authenticate its binding evidence"
        )


def _require_exact_nested_object(
    value: object,
    fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise TrustedTimeGracefulStopV2Rejected(f"{label} must be one exact object")
    _require_fields(value, fields)
    return value


def _require_exact_nested_object_list(
    value: object,
    *,
    length: int,
    label: str,
) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != length:
        raise TrustedTimeGracefulStopV2Rejected(f"{label} length is not exact")
    result: list[dict[str, object]] = []
    for item in value:
        if type(item) is not dict:
            raise TrustedTimeGracefulStopV2Rejected(
                f"{label} contains a non-object value"
            )
        result.append(item)
    return result


def _require_exact_sha256_list(
    value: object,
    *,
    length: int,
    label: str,
) -> list[str]:
    if type(value) is not list or len(value) != length:
        raise TrustedTimeGracefulStopV2Rejected(f"{label} length is not exact")
    return [_require_sha256(item, label) for item in value]


def _nested_domain_sha256(domain: str, value: object) -> str:
    return _domain_sha256(
        domain,
        canonical_v2_json_bytes(
            value,
            maximum_bytes=LIFECYCLE_V2_RECORD_MAXIMUM_BYTES,
        ),
    )


def _validate_docker_connection_identity(
    value: object,
    *,
    expected_ordinal: int,
    environment: object,
    graceful_stop_operation_id: str,
) -> tuple[dict[str, object], str]:
    fields = _require_exact_nested_object(
        value,
        _DOCKER_CONNECTION_FIELDS,
        "Docker connection identity",
    )
    if (
        fields["contract_version"]
        != "phase6d-trusted-time-graceful-stop-docker-connection-identity-v2"
        or fields["service"] != "trusted-time-graceful-stop-docker-v2"
        or fields["status"] != "docker_connection_bound"
        or fields["environment"] != environment
        or fields["graceful_stop_operation_id"] != graceful_stop_operation_id
        or fields["api_version"] != "v1.45"
        or fields["docker_socket_path"] != "/var/run/docker.sock"
        or fields["connection_ordinal"] != expected_ordinal
        or any(fields[name] != 0 for name in ("peer_uid", "peer_gid"))
        or any(
            fields[name] != 0
            for name in (
                "socket_path_uid",
                "socket_path_gid",
                "daemon_executable_uid",
                "daemon_executable_gid",
            )
        )
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker connection identity discriminator is invalid"
        )
    _require_sha256(fields["channel_id"], "channel_id")
    _require_sha256(
        fields["admitted_daemon_info_projection_sha256"],
        "admitted_daemon_info_projection_sha256",
    )
    for name in ("daemon_executable_sha256", "daemon_cgroup_sha256"):
        _require_sha256(fields[name], name)
    positive_names = (
        "socket_mount_id",
        "socket_mount_parent_id",
        "socket_path_device",
        "socket_path_inode",
        "peer_pid",
        "daemon_start_time_ticks",
        "daemon_proc_device",
        "daemon_proc_inode",
        "daemon_pid_namespace_inode",
        "daemon_executable_device",
        "daemon_executable_inode",
        "daemon_executable_size",
        "daemon_executable_nlink",
        "local_socket_device",
        "local_socket_inode",
        "local_socket_cookie",
    )
    for name in positive_names:
        _require_int(fields[name], name, minimum=1)
    checkpoints = [
        _require_int(fields[name], name)
        for name in (
            "path_preconnect_validated_boottime_ns",
            "opened_boottime_ns",
            "pre_request_revalidated_boottime_ns",
            "response_headers_revalidated_boottime_ns",
            "response_complete_revalidated_boottime_ns",
        )
    ]
    deadline = _require_int(fields["call_deadline_boottime_ns"], "call_deadline_boottime_ns")
    if checkpoints != sorted(checkpoints) or checkpoints[-1] >= deadline:
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker connection checkpoints are invalid"
        )
    return fields, _nested_domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/docker-connection-identity/v2",
        fields,
    )


def _validate_docker_exchange(
    value: object,
    *,
    exchange_kind: str,
    target_kind: str,
    target_identity: object,
    http_status: int,
) -> tuple[dict[str, object], str]:
    fields = _require_exact_nested_object(
        value,
        _DOCKER_EXCHANGE_FIELDS,
        "Docker HTTP exchange",
    )
    if (
        fields["exchange_kind"] != exchange_kind
        or fields["target_kind"] != target_kind
        or fields["target_identity"] != target_identity
        or fields["http_status"] != http_status
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker HTTP exchange discriminator is invalid"
        )
    for name in (
        "request_semantic_sha256",
        "connection_identity_sha256",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "trace_entry_sha256",
    ):
        _require_sha256(fields[name], name)
    started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
    completed = _require_int(
        fields["call_completed_boottime_ns"],
        "call_completed_boottime_ns",
    )
    if completed < started:
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker HTTP exchange completion precedes its start"
        )
    return fields, _nested_domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/docker-http-exchange/v2",
        fields,
    )


def _validate_docker_trace_entry(
    value: object,
    *,
    expected_ordinal: int,
) -> tuple[dict[str, object], str]:
    fields = _require_exact_nested_object(
        value,
        _DOCKER_TRACE_FIELDS,
        "Docker trace entry",
    )
    if fields["trace_ordinal"] != expected_ordinal:
        raise TrustedTimeGracefulStopV2Rejected("Docker trace ordinal is invalid")
    for name in (
        "request_semantic_sha256",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "connection_identity_sha256",
        "previous_trace_entry_sha256",
    ):
        _require_sha256(fields[name], name)
    _require_int(fields["http_status"], "http_status", minimum=100)
    started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
    completed = _require_int(
        fields["call_completed_boottime_ns"],
        "call_completed_boottime_ns",
    )
    if completed < started:
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker trace completion precedes its start"
        )
    return fields, _nested_domain_sha256(
        "autoquant.trusted-time.docker-trace-entry.v2",
        fields,
    )


def _require_docker_exchange_trace_binding(
    *,
    connection: dict[str, object],
    connection_sha256: str,
    exchange: dict[str, object],
    trace: dict[str, object],
    trace_sha256: str,
) -> None:
    common_names = (
        "request_semantic_sha256",
        "http_status",
        "response_framing_sha256",
        "response_body_sha256",
        "response_projection_sha256",
        "call_started_boottime_ns",
        "call_completed_boottime_ns",
    )
    if (
        exchange["connection_identity_sha256"] != connection_sha256
        or trace["connection_identity_sha256"] != connection_sha256
        or exchange["trace_entry_sha256"] != trace_sha256
        or any(exchange[name] != trace[name] for name in common_names)
        or connection["path_preconnect_validated_boottime_ns"]
        != exchange["call_started_boottime_ns"]
        or connection["response_complete_revalidated_boottime_ns"]
        != exchange["call_completed_boottime_ns"]
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker connection, exchange, and trace nesting disagrees"
        )


def _validate_docker_mutation_result_evidence(
    stage: LifecycleV2Stage,
    value: dict[str, object],
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
) -> None:
    semantic = _require_exact_nested_object(
        value["result_semantic"],
        _DOCKER_MUTATION_SEMANTIC_FIELDS,
        "Docker mutation result semantic",
    )
    (
        contract,
        status,
        result_kind,
        target_kind,
        outcome,
        primary_ordinal,
        post_status,
    ) = _DOCKER_RESULT_RULE_BY_STAGE[stage]
    if (
        semantic["contract_version"] != contract
        or semantic["service"] != "trusted-time-graceful-stop-docker-v2"
        or semantic["status"] != status
        or semantic["graceful_stop_operation_id"] != graceful_stop_operation_id
        or semantic["root_sha256"] != root_sha256
        or semantic["result_kind"] != result_kind
        or semantic["target_kind"] != target_kind
        or semantic["outcome"] != outcome
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker mutation result semantic discriminator is invalid"
        )
    for name in (
        "root_sha256",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
        "primary_request_semantic_sha256",
        "primary_connection_identity_sha256",
        "primary_exchange_sha256",
        "post_inspect_request_semantic_sha256",
        "post_inspect_connection_identity_sha256",
        "post_inspect_exchange_sha256",
    ):
        _require_sha256(semantic[name], name)
    primary_connection, primary_connection_sha256 = (
        _validate_docker_connection_identity(
            semantic["primary_connection_identity"],
            expected_ordinal=primary_ordinal,
            environment=semantic["environment"],
            graceful_stop_operation_id=graceful_stop_operation_id,
        )
    )
    post_connection, post_connection_sha256 = _validate_docker_connection_identity(
        semantic["post_inspect_connection_identity"],
        expected_ordinal=primary_ordinal + 1,
        environment=semantic["environment"],
        graceful_stop_operation_id=graceful_stop_operation_id,
    )
    primary_exchange, primary_exchange_sha256 = _validate_docker_exchange(
        semantic["primary_exchange"],
        exchange_kind="mutation",
        target_kind=target_kind,
        target_identity=semantic["target_id"],
        http_status=204,
    )
    post_exchange, post_exchange_sha256 = _validate_docker_exchange(
        semantic["post_inspect_exchange"],
        exchange_kind="post_inspect",
        target_kind=target_kind,
        target_identity=semantic["target_id"],
        http_status=post_status,
    )
    trace_values = _require_exact_nested_object_list(
        semantic["ordered_trace_entry_list"],
        length=2,
        label="Docker mutation trace list",
    )
    trace_digest_list = _require_exact_sha256_list(
        semantic["ordered_trace_entry_sha256_list"],
        length=2,
        label="Docker mutation trace digest list",
    )
    primary_trace, primary_trace_sha256 = _validate_docker_trace_entry(
        trace_values[0],
        expected_ordinal=primary_ordinal,
    )
    post_trace, post_trace_sha256 = _validate_docker_trace_entry(
        trace_values[1],
        expected_ordinal=primary_ordinal + 1,
    )
    _require_docker_exchange_trace_binding(
        connection=primary_connection,
        connection_sha256=primary_connection_sha256,
        exchange=primary_exchange,
        trace=primary_trace,
        trace_sha256=primary_trace_sha256,
    )
    _require_docker_exchange_trace_binding(
        connection=post_connection,
        connection_sha256=post_connection_sha256,
        exchange=post_exchange,
        trace=post_trace,
        trace_sha256=post_trace_sha256,
    )
    connection_digest_list = _require_exact_sha256_list(
        semantic["ordered_connection_identity_sha256_list"],
        length=2,
        label="Docker mutation connection digest list",
    )
    domain = {
        "container_stop": (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "docker-container-stop-result/v2"
        ),
        "container_remove": (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "docker-container-remove-result/v2"
        ),
        "network_remove": (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "docker-network-remove-result/v2"
        ),
    }[result_kind]
    semantic_sha256 = _nested_domain_sha256(domain, semantic)
    if (
        primary_connection["channel_id"] != post_connection["channel_id"]
        or semantic["primary_connection_identity_sha256"]
        != primary_connection_sha256
        or semantic["post_inspect_connection_identity_sha256"]
        != post_connection_sha256
        or connection_digest_list
        != [primary_connection_sha256, post_connection_sha256]
        or semantic["primary_exchange_sha256"] != primary_exchange_sha256
        or semantic["post_inspect_exchange_sha256"] != post_exchange_sha256
        or trace_digest_list != [primary_trace_sha256, post_trace_sha256]
        or post_trace["previous_trace_entry_sha256"] != primary_trace_sha256
        or primary_exchange["request_semantic_sha256"]
        != semantic["primary_request_semantic_sha256"]
        or post_exchange["request_semantic_sha256"]
        != semantic["post_inspect_request_semantic_sha256"]
        or value["docker_request_semantic_sha256"]
        != semantic["primary_request_semantic_sha256"]
        or value["docker_post_inspect_request_semantic_sha256"]
        != semantic["post_inspect_request_semantic_sha256"]
        or value["docker_method_trace_entry_sha256_list"] != trace_digest_list
        or value["responder_identity_sha256"]
        != semantic["admitted_daemon_info_projection_sha256"]
        or value["disposition"] != semantic["outcome"]
        or value["call_started_boottime_ns"]
        != semantic["call_started_boottime_ns"]
        or value["call_completed_boottime_ns"]
        != semantic["call_completed_boottime_ns"]
        or value["result_semantic_sha256"] != semantic_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker mutation result crossed its exact nested semantic"
        )


def _validate_docker_volume_result_evidence(
    value: dict[str, object],
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
) -> None:
    semantic = _require_exact_nested_object(
        value["result_semantic"],
        _DOCKER_VOLUME_SEMANTIC_FIELDS,
        "Docker volume result semantic",
    )
    expected_volume_names = [
        "autoquanttrader-trusted-time_chrony_command_socket",
        "autoquanttrader-trusted-time_chrony_state",
    ]
    if (
        semantic["contract_version"]
        != "phase6d-trusted-time-graceful-stop-docker-volume-preservation-result-v2"
        or semantic["service"] != "trusted-time-graceful-stop-docker-v2"
        or semantic["status"] != "named_volumes_preserved"
        or semantic["graceful_stop_operation_id"] != graceful_stop_operation_id
        or semantic["root_sha256"] != root_sha256
        or semantic["result_kind"] != "volume_preservation"
        or semantic["target_kind"] != "named_volume_set"
        or semantic["target_names"] != expected_volume_names
        or semantic["outcome"] != "volumes_preserved"
        or semantic["volume_delete_call_count"] != 0
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker volume result semantic discriminator is invalid"
        )
    for name in (
        "root_sha256",
        "docker_admission_capture_sha256",
        "admitted_daemon_info_projection_sha256",
    ):
        _require_sha256(semantic[name], name)
    request_digests = _require_exact_sha256_list(
        semantic["ordered_request_semantic_sha256_list"],
        length=2,
        label="Docker volume request digest list",
    )
    admission_volumes = _require_exact_sha256_list(
        semantic["admission_volume_projection_sha256_list"],
        length=2,
        label="Docker admitted volume projection list",
    )
    post_volumes = _require_exact_sha256_list(
        semantic["post_volume_projection_sha256_list"],
        length=2,
        label="Docker post-volume projection list",
    )
    connection_values = _require_exact_nested_object_list(
        semantic["ordered_connection_identity_list"],
        length=2,
        label="Docker volume connection list",
    )
    exchange_values = _require_exact_nested_object_list(
        semantic["ordered_http_exchange_list"],
        length=2,
        label="Docker volume exchange list",
    )
    trace_values = _require_exact_nested_object_list(
        semantic["ordered_trace_entry_list"],
        length=2,
        label="Docker volume trace list",
    )
    connection_digest_list = _require_exact_sha256_list(
        semantic["ordered_connection_identity_sha256_list"],
        length=2,
        label="Docker volume connection digest list",
    )
    exchange_digest_list = _require_exact_sha256_list(
        semantic["ordered_http_exchange_sha256_list"],
        length=2,
        label="Docker volume exchange digest list",
    )
    trace_digest_list = _require_exact_sha256_list(
        semantic["ordered_trace_entry_sha256_list"],
        length=2,
        label="Docker volume trace digest list",
    )
    connections: list[dict[str, object]] = []
    connection_sha256s: list[str] = []
    exchanges: list[dict[str, object]] = []
    exchange_sha256s: list[str] = []
    traces: list[dict[str, object]] = []
    trace_sha256s: list[str] = []
    for index in range(2):
        connection, connection_sha256 = _validate_docker_connection_identity(
            connection_values[index],
            expected_ordinal=16 + index,
            environment=semantic["environment"],
            graceful_stop_operation_id=graceful_stop_operation_id,
        )
        exchange, exchange_sha256 = _validate_docker_exchange(
            exchange_values[index],
            exchange_kind="volume_proof",
            target_kind="volume",
            target_identity=expected_volume_names[index],
            http_status=200,
        )
        trace, trace_sha256 = _validate_docker_trace_entry(
            trace_values[index],
            expected_ordinal=16 + index,
        )
        _require_docker_exchange_trace_binding(
            connection=connection,
            connection_sha256=connection_sha256,
            exchange=exchange,
            trace=trace,
            trace_sha256=trace_sha256,
        )
        connections.append(connection)
        connection_sha256s.append(connection_sha256)
        exchanges.append(exchange)
        exchange_sha256s.append(exchange_sha256)
        traces.append(trace)
        trace_sha256s.append(trace_sha256)
    semantic_sha256 = _nested_domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/"
        "docker-volume-preservation-result/v2",
        semantic,
    )
    if (
        connections[0]["channel_id"] != connections[1]["channel_id"]
        or connection_digest_list != connection_sha256s
        or exchange_digest_list != exchange_sha256s
        or trace_digest_list != trace_sha256s
        or traces[1]["previous_trace_entry_sha256"] != trace_sha256s[0]
        or any(
            exchanges[index]["request_semantic_sha256"] != request_digests[index]
            for index in range(2)
        )
        or any(
            exchanges[index]["response_projection_sha256"] != post_volumes[index]
            for index in range(2)
        )
        or admission_volumes != post_volumes
        or value["command_socket_volume_identity_sha256"] != admission_volumes[0]
        or value["state_volume_identity_sha256"] != admission_volumes[1]
        or value["docker_api_trace_sha256"] != trace_sha256s[-1]
        or value["docker_request_semantic_sha256_list"] != request_digests
        or value["docker_method_trace_entry_sha256_list"] != trace_sha256s
        or value["responder_identity_sha256"]
        != semantic["admitted_daemon_info_projection_sha256"]
        or value["disposition"] != semantic["outcome"]
        or value["call_started_boottime_ns"]
        != semantic["proof_started_boottime_ns"]
        or value["call_completed_boottime_ns"]
        != semantic["proof_completed_boottime_ns"]
        or value["volume_delete_call_count"] != 0
        or value["result_semantic_sha256"] != semantic_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "Docker volume result crossed its exact nested semantic"
        )


def _validate_wire_publication_receipt_evidence(
    stage: LifecycleV2Stage,
    value: dict[str, object],
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
) -> None:
    receipt = _require_exact_nested_object(
        value["wire_publication_receipt"],
        _WIRE_PUBLICATION_RECEIPT_FIELDS,
        "wire publication receipt",
    )
    is_result = stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
    prefix = "clean_stop_result" if is_result else "clean_stop_error"
    expected_frame = "clean_stop_result" if is_result else "clean_stop_error"
    expected_kind = "signed_result_envelope" if is_result else "signed_error_envelope"
    if (
        receipt["contract_version"]
        != "phase6d-post-enrollment-graceful-stop-wire-envelope-publication-receipt-v2"
        or receipt["service"]
        != "trusted-time-post-enrollment-graceful-stop-lifecycle-v2"
        or receipt["status"] != "wire_envelope_published"
        or receipt["graceful_stop_operation_id"] != graceful_stop_operation_id
        or receipt["root_sha256"] != root_sha256
        or receipt["artifact_kind"] != expected_kind
        or receipt["frame_type"] != expected_frame
        or receipt["file_mode"] != 0o600
        or receipt["directory_fsync_completed"] is not True
        or receipt["stable_readback_completed"] is not True
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "wire publication receipt discriminator is invalid"
        )
    for name in (
        "artifact_directory_device",
        "artifact_directory_inode",
        "file_device",
        "file_inode",
        "file_size",
        "key_generation",
        "message_counter",
    ):
        _require_int(receipt[name], name, minimum=1)
    authorized = _require_int(
        receipt["publication_authorized_boottime_ns"],
        "publication_authorized_boottime_ns",
    )
    deadline = _require_int(receipt["deadline_boottime_ns"], "deadline_boottime_ns")
    for name in (
        "root_sha256",
        "signed_envelope_sha256",
        "payload_sha256",
        "signature_sha256",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
    ):
        _require_sha256(receipt[name], name)
    artifact_path = receipt["artifact_path"]
    directory_path = receipt["artifact_directory_path"]
    file_name = receipt["file_name"]
    if (
        authorized >= deadline
        or type(directory_path) is not str
        or type(file_name) is not str
        or artifact_path != f"{directory_path}/{file_name}"
        or value[f"{prefix}_artifact_path"] != artifact_path
        or value[f"{prefix}_artifact_name"] != file_name
        or value[f"{prefix}_sha256"] != receipt["signed_envelope_sha256"]
        or value[f"{prefix}_payload_sha256"] != receipt["payload_sha256"]
        or value[f"{prefix}_signature_sha256"] != receipt["signature_sha256"]
        or value["envelope_contract_version"] != receipt["envelope_contract_version"]
        or value["frame_type"] != receipt["frame_type"]
        or value["payload_contract_version"] != receipt["payload_contract_version"]
        or value["key_generation"] != receipt["key_generation"]
        or value["signing_key_id"] != receipt["signing_key_id"]
        or value["channel_id"] != receipt["channel_id"]
        or value["lifecycle_dispatch_prefix_sha256"]
        != receipt["lifecycle_dispatch_prefix_sha256"]
        or value["message_counter"] != receipt["message_counter"]
        or value["deadline_boottime_ns"] != deadline
        or value["wire_publication_receipt_sha256"]
        != _nested_domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "wire-envelope-publication-receipt/v2",
            receipt,
        )
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "wire publication receipt crossed its exact ordinal-two evidence"
        )


def _validate_terminal_cleanup_result_evidence(
    value: dict[str, object],
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
    predecessor_sha256: str,
) -> None:
    completed = _require_int(
        value["cleanup_completed_boottime_ns"],
        "cleanup_completed_boottime_ns",
    )
    if value["cleanup_intent_sha256"] != predecessor_sha256:
        raise TrustedTimeGracefulStopV2Rejected(
            "terminal cleanup result does not bind its exact intent predecessor"
        )
    absence_specs = (
        (
            "socket_absence",
            "socket_absence_sha256",
            "transport_socket",
            ["/run/autoquant/trusted-time/graceful-stop-v2/transport/supervisor.sock"],
        ),
        (
            "credential_path_absence",
            "credential_path_absence_sha256",
            "credential_paths",
            [
                "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets/host-ed25519.raw",
                (
                    "/run/autoquant/trusted-time/graceful-stop-v2/"
                    "supervisor-secrets/supervisor-ed25519.raw"
                ),
            ],
        ),
    )
    absence_times: list[int] = []
    for nested_name, digest_name, kind, paths in absence_specs:
        absence = _require_exact_nested_object(
            value[nested_name],
            _TERMINAL_PATH_ABSENCE_FIELDS,
            nested_name,
        )
        _require_identifier(absence["environment"], "environment")
        observed = _require_int(absence["observed_boottime_ns"], "observed_boottime_ns")
        if (
            absence["graceful_stop_operation_id"] != graceful_stop_operation_id
            or absence["lifecycle_root_sha256"] != root_sha256
            or absence["absence_kind"] != kind
            or absence["paths"] != paths
            or absence["all_absent"] is not True
            or observed > completed
            or value[digest_name]
            != _nested_domain_sha256(
                "AutoQuantTrader/trusted-time/graceful-stop/"
                f"{kind.replace('_', '-')}-absence/v2",
                absence,
            )
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "terminal cleanup path absence is not exact"
            )
        absence_times.append(observed)
    projection = _require_exact_nested_object(
        value["empty_mount_projection"],
        _TERMINAL_EMPTY_MOUNT_PROJECTION_FIELDS,
        "empty mount projection",
    )
    mount_values = _require_exact_nested_object_list(
        projection["mounts"],
        length=3,
        label="empty mount projection mount list",
    )
    _require_identifier(projection["environment"], "environment")
    mount_rules = {
        "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets": (0, 0, 0o700),
        "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets": (
            0,
            10_001,
            0o730,
        ),
        "/run/autoquant/trusted-time/graceful-stop-v2/transport": (0, 10_001, 0o770),
    }
    mount_ids: dict[str, int] = {}
    for mount in mount_values:
        _require_fields(mount, _TERMINAL_EMPTY_MOUNT_IDENTITY_FIELDS)
        path = mount["path"]
        rule = mount_rules.get(path) if type(path) is str else None
        mount_id = _require_int(mount["mount_id"], "mount_id", minimum=1)
        _require_int(mount["mount_parent_id"], "mount_parent_id", minimum=1)
        _require_int(mount["directory_device"], "directory_device", minimum=1)
        _require_int(mount["directory_inode"], "directory_inode", minimum=1)
        if (
            rule is None
            or mount["mount_root"] != "/"
            or mount["mount_options"]
            != ["nodev", "noexec", "nosuid", "rw", "size=64K"]
            or mount["directory_uid"] != rule[0]
            or mount["directory_gid"] != rule[1]
            or mount["directory_mode"] != rule[2]
            or mount["entry_count"] != 0
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "empty mount projection identity is invalid"
            )
        mount_ids[cast(str, path)] = mount_id
    if (
        projection["graceful_stop_operation_id"] != graceful_stop_operation_id
        or projection["lifecycle_root_sha256"] != root_sha256
        or list(mount_ids) != sorted(mount_rules)
        or len(set(mount_ids.values())) != 3
        or value["empty_mount_projection_sha256"]
        != _nested_domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "empty-secret-mount-projection/v2",
            projection,
        )
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "empty mount projection crossed terminal cleanup"
        )
    unmount = _require_exact_nested_object(
        value["unmount_receipt"],
        _TERMINAL_UNMOUNT_RECEIPT_FIELDS,
        "secret mount unmount receipt",
    )
    unmount_values = _require_exact_nested_object_list(
        unmount["mounts"],
        length=3,
        label="secret mount unmount receipt list",
    )
    expected_unmount_paths = (
        "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets",
        "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets",
        "/run/autoquant/trusted-time/graceful-stop-v2/transport",
    )
    unmount_times: list[int] = []
    for index, entry in enumerate(unmount_values):
        _require_fields(entry, _TERMINAL_UNMOUNT_ENTRY_FIELDS)
        entry_completed = _require_int(
            entry["completed_boottime_ns"],
            "completed_boottime_ns",
        )
        if (
            entry["mount_id"] != mount_ids[expected_unmount_paths[index]]
            or entry["unmounted"] is not True
            or entry["mount_absent"] is not True
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "secret mount unmount receipt changed mount identity"
            )
        unmount_times.append(entry_completed)
    if (
        unmount["environment"] != projection["environment"]
        or unmount["graceful_stop_operation_id"] != graceful_stop_operation_id
        or unmount["lifecycle_root_sha256"] != root_sha256
        or unmount_times != sorted(unmount_times)
        or unmount_times[-1] > completed
        or value["unmount_receipt_sha256"]
        != _nested_domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "secret-mount-unmount-receipt/v2",
            unmount,
        )
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "secret mount unmount receipt crossed terminal cleanup"
        )
    native = _require_exact_nested_object(
        value["native_owner_cleanup_receipt"],
        _TERMINAL_NATIVE_OWNER_CLEANUP_RECEIPT_FIELDS,
        "native owner cleanup receipt",
    )
    native_completed = _require_int(
        native["completed_boottime_ns"],
        "completed_boottime_ns",
    )
    for name in (
        "lifecycle_root_sha256",
        "channel_id",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "native_owner_set_sha256",
    ):
        _require_sha256(native[name], name)
    if (
        native["environment"] != projection["environment"]
        or native["graceful_stop_operation_id"] != graceful_stop_operation_id
        or native["lifecycle_root_sha256"] != root_sha256
        or _require_int(native["owner_count_before"], "owner_count_before", minimum=1)
        < 1
        or native["owner_count_after"] != 0
        or native["every_owner_invalidated"] is not True
        or native["every_private_buffer_zeroized_or_process_destroyed"] is not True
        or native_completed > completed
        or value["native_owner_cleanup_receipt_sha256"]
        != _nested_domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "native-owner-cleanup-receipt/v2",
            native,
        )
        or completed < max(*absence_times, *unmount_times, native_completed)
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "native owner cleanup receipt crossed terminal cleanup"
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


def _validate_evidence(
    stage: LifecycleV2Stage,
    evidence: FrozenJsonObject,
    *,
    graceful_stop_operation_id: str,
    root_sha256: str,
    predecessor_sha256: str,
    deadline_boottime_ns: int,
) -> None:
    value = evidence.to_dict()
    if FrozenJsonObject.capture(value) != evidence:
        raise TrustedTimeGracefulStopV2Rejected("progress evidence is not canonically frozen")
    _require_fields(value, _expected_evidence_fields(stage))
    for name, item in value.items():
        if name.endswith("_sha256"):
            _require_sha256(item, name)
        elif name.endswith("_sha256_list"):
            if type(item) is not list or not item:
                raise TrustedTimeGracefulStopV2Rejected(f"{name} must be a nonempty list")
            for digest in item:
                _require_sha256(digest, name)
    if (
        "intent_sha256" in value
        and value["intent_sha256"] != predecessor_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "result evidence intent does not match its exact predecessor"
        )
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
    if stage in {
        LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
    }:
        _require_int(value["key_generation"], "key_generation", minimum=1)
        if _require_int(value["message_counter"], "message_counter", minimum=1) != 1:
            raise TrustedTimeGracefulStopV2Rejected(
                "message_counter is not the exact terminal-frame counter"
            )
        _validate_wire_publication_receipt_evidence(
            stage,
            value,
            graceful_stop_operation_id=graceful_stop_operation_id,
            root_sha256=root_sha256,
        )
    if stage in _REAUTHENTICATION_RESULT_STAGES | _DOCKER_RESULT_STAGES | {
        LifecycleV2Stage.NAMED_VOLUMES_PRESERVED
    }:
        started = _require_int(value["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(value["call_completed_boottime_ns"], "call_completed_boottime_ns")
        if completed < started:
            raise TrustedTimeGracefulStopV2Rejected("result completion precedes call start")
    if stage in _REAUTHENTICATION_RESULT_STAGES:
        _validate_reauthentication_result_evidence(
            stage,
            value,
            graceful_stop_operation_id=graceful_stop_operation_id,
            root_sha256=root_sha256,
        )
    if stage in _DOCKER_RESULT_STAGES:
        _validate_docker_mutation_result_evidence(
            stage,
            value,
            graceful_stop_operation_id=graceful_stop_operation_id,
            root_sha256=root_sha256,
        )
    if stage is LifecycleV2Stage.NAMED_VOLUMES_PRESERVED:
        _validate_docker_volume_result_evidence(
            value,
            graceful_stop_operation_id=graceful_stop_operation_id,
            root_sha256=root_sha256,
        )
    if stage is LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED:
        _validate_terminal_cleanup_result_evidence(
            value,
            graceful_stop_operation_id=graceful_stop_operation_id,
            root_sha256=root_sha256,
            predecessor_sha256=predecessor_sha256,
        )
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
    if (
        stage is LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED
        and value["cleanup_deadline_boottime_ns"] != deadline_boottime_ns
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "terminal cleanup intent deadline does not match its record deadline"
        )
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
    if stage is LifecycleV2Stage.NAMED_VOLUMES_PRESERVED:
        volume_delete_call_count = _require_int(
            value["volume_delete_call_count"],
            "volume_delete_call_count",
        )
        if volume_delete_call_count != 0:
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
        _validate_evidence(
            self.stage,
            self.evidence,
            graceful_stop_operation_id=self.graceful_stop_operation_id,
            root_sha256=self.root_sha256,
            predecessor_sha256=self.predecessor_sha256,
            deadline_boottime_ns=self.deadline_boottime_ns,
        )
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
            wire_sha256 = _require_sha256(
                self.wire_artifact_sha256,
                "wire_artifact_sha256",
            )
            result_stage = self.stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            wire_type = "result" if result_stage else "error"
            expected_kind = f"signed_{wire_type}_envelope"
            expected_name = (
                f"trusted-time-post-enrollment-graceful-stop-v2-wire-{wire_type}-{wire_sha256}.json"
            )
            if self.wire_artifact_kind != expected_kind:
                raise TrustedTimeGracefulStopV2Rejected(
                    "wire artifact kind does not match its terminal stage"
                )
            if self.wire_artifact_file_name != expected_name:
                raise TrustedTimeGracefulStopV2Rejected(
                    "wire artifact filename is not digest-derived"
                )
            path = self.wire_artifact_path
            if (
                type(path) is not str
                or not path.startswith("/")
                or not path.endswith(f"/{expected_name}")
                or "//" in path
                or "/./" in path
                or "/../" in path
                or "\0" in path
                or len(path.encode("utf-8")) > 4_096
            ):
                raise TrustedTimeGracefulStopV2Rejected("wire artifact path is not exact")
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
    last_ordinal = _require_int(value["last_ordinal"], "last_ordinal")
    entry_count = _require_int(value["entry_count"], "entry_count", minimum=1)
    if (
        last_ordinal != transcript.entries[-1].ordinal
        or value["last_stage"] != transcript.entries[-1].stage.value
        or entry_count != len(transcript.entries)
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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2CleanStopRequestBasis:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("clean-stop request bases require canonical capture or root derivation")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        _validate_request_common(frozen.to_dict(), final=False)
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @classmethod
    def from_root(cls, root: LifecycleV2Root) -> Self:
        if type(root) is not LifecycleV2Root:
            raise TrustedTimeGracefulStopV2Rejected("request basis requires an exact root")
        return cls.capture(
            {
                "contract_version": LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION,
                "service": LIFECYCLE_V2_CLEAN_STOP_SERVICE,
                "status": "operation_bound_clean_stop_request_basis_retained",
                "environment": root.environment,
                "graceful_stop_operation_id": root.graceful_stop_operation_id,
                "graceful_stop_target_sha256": root.graceful_stop_target_sha256,
                "graceful_stop_decision_v1_sha256": root.graceful_stop_decision_v1_sha256,
                "historical_decision_receipt_sha256": root.historical_decision_receipt_sha256,
                "graceful_stop_operator_attestation_envelope_sha256": (
                    root.graceful_stop_operator_attestation_envelope_sha256
                ),
                "lifecycle_root_sha256": root.sha256,
                "admission_sha256": root.admission_sha256,
                "topology_sha256": root.topology_sha256,
                "topology_lease_sha256": root.topology_lease_sha256,
                "trusted_head_sha256": root.trusted_head_sha256,
                "supervisor_container_id": root.supervisor_container_id,
                "channel_id": root.channel_id,
                "boot_epoch_sha256": root.boot_epoch_sha256,
                "host_process_epoch_sha256": root.host_process_epoch_sha256,
                "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
                "checkpoint_reason": "clean_stop",
                "exact_new_record_required": True,
                "clean_stop_result_deadline_boottime_ns": (
                    root.clean_stop_result_deadline_boottime_ns
                ),
                "transport_cleanup_required": True,
                "transport_cleanup_deadline_boottime_ns": min(
                    root.clean_stop_result_deadline_boottime_ns + LIFECYCLE_V2_COMMIT_BUDGET_NS,
                    root.operation_deadline_boottime_ns,
                ),
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            }
        )

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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2CleanStopRequest:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("clean-stop requests require canonical capture or prefix derivation")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        _validate_request_common(frozen.to_dict(), final=True)
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @classmethod
    def from_prefix(
        cls,
        root: LifecycleV2Root,
        basis: LifecycleV2CleanStopRequestBasis,
        request_intent: LifecycleV2ProgressRecord,
    ) -> Self:
        if (
            type(root) is not LifecycleV2Root
            or type(basis) is not LifecycleV2CleanStopRequestBasis
            or basis != LifecycleV2CleanStopRequestBasis.from_root(root)
            or type(request_intent) is not LifecycleV2ProgressRecord
            or request_intent.ordinal != 1
            or request_intent.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
            or request_intent.root_sha256 != root.sha256
            or request_intent.graceful_stop_operation_id != root.graceful_stop_operation_id
            or request_intent.predecessor_sha256 != root.sha256
            or request_intent.evidence.to_dict()["arguments_sha256"] != basis.sha256
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "request must derive from one exact root/basis/intent prefix"
            )
        value = basis.to_dict()
        value["contract_version"] = LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION
        value["status"] = "operation_bound_clean_stop_requested"
        value["request_basis_sha256"] = basis.sha256
        value["request_intent_sha256"] = request_intent.sha256
        value["lifecycle_dispatch_prefix_sha256"] = lifecycle_v2_dispatch_prefix_sha256(
            root, request_intent
        )
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


@dataclass(frozen=True, slots=True, init=False)
class UnverifiedLifecycleV2TransportEnvelope:
    """Structurally exact signed bytes; cryptographic authentication is separate."""

    fields: FrozenJsonObject
    payload: bytes
    signature: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport envelopes require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _TRANSPORT_ENVELOPE_FIELDS)
        if (
            fields["contract_version"] != LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_TRANSPORT_SERVICE
            or fields["protocol_version"] != 2
            or type(fields["frame_type"]) is not str
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
        _require_int(fields["message_counter"], "message_counter")
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
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "payload", payload)
        object.__setattr__(result, "signature", signature)
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


@dataclass(frozen=True, slots=True, eq=False, init=False)
class _FakeAuthenticatedLifecycleV2TransportEnvelope:
    """Registry-issued test-only authentication receipt."""

    envelope: UnverifiedLifecycleV2TransportEnvelope
    root_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fake transport authentication requires test-only issuance")


def decode_unverified_lifecycle_v2_transport_envelope(
    encoded: object,
) -> UnverifiedLifecycleV2TransportEnvelope:
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES)
    )


def _build_fake_lifecycle_v2_transport_authentication_endpoints() -> tuple[
    Callable[..., _FakeAuthenticatedLifecycleV2TransportEnvelope],
    Callable[..., UnverifiedLifecycleV2TransportEnvelope],
]:
    """Keep fake issuance test-only, root-bound, and free of caller-held tokens."""

    seal_runtime: Callable[..., bool]
    require_runtime: Callable[..., Any]
    decode_envelope = decode_unverified_lifecycle_v2_transport_envelope
    decode_root = decode_lifecycle_v2_root
    fake_type = _FakeAuthenticatedLifecycleV2TransportEnvelope
    envelope_type = UnverifiedLifecycleV2TransportEnvelope
    root_type = LifecycleV2Root

    def require_test_root(root: object) -> LifecycleV2Root:
        if type(root) is not root_type:
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication requires an exact test root"
            )
        try:
            exact_root = decode_root(root.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication requires an exact test root"
            ) from error
        if exact_root != root or exact_root.environment != "test":
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication requires an exact test root"
            )
        return exact_root

    def require_root_bound_envelope(
        envelope: object,
        root: LifecycleV2Root,
    ) -> UnverifiedLifecycleV2TransportEnvelope:
        if type(envelope) is not envelope_type:
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication requires an exact terminal envelope"
            )
        try:
            exact_envelope = decode_envelope(envelope.encoded)
            fields = exact_envelope.to_dict()
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication requires an exact terminal envelope"
            ) from error
        expected = {
            "environment": "test",
            "key_generation": root.transport_key_generation,
            "signing_key_id": root.supervisor_transport_key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        }
        if (
            exact_envelope != envelope
            or exact_envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}
            or any(fields[name] != value for name, value in expected.items())
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "fake terminal envelope crossed its exact test root"
            )
        return exact_envelope

    def snapshot(
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root_sha256: str,
    ) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/fake-transport-authentication/v2",
            canonical_v2_json_bytes(
                {
                    "envelope": envelope.to_dict(),
                    "root_sha256": root_sha256,
                },
                maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES,
            ),
        )

    def issue(
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        *,
        root: LifecycleV2Root,
    ) -> _FakeAuthenticatedLifecycleV2TransportEnvelope:
        exact_root = require_test_root(root)
        exact_envelope = require_root_bound_envelope(envelope, exact_root)
        result = object.__new__(fake_type)
        object.__setattr__(result, "envelope", exact_envelope)
        object.__setattr__(result, "root_sha256", exact_root.sha256)
        if not seal_runtime(
            result,
            snapshot_sha256=snapshot(exact_envelope, exact_root.sha256),
            kind="fake_authenticated_terminal_envelope",
            provenance="test_only_fake_transport",
            scope_sha256=exact_root.sha256,
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "fake transport authentication could not be sealed"
            )
        return result

    def require(
        value: object,
        *,
        root: LifecycleV2Root,
    ) -> UnverifiedLifecycleV2TransportEnvelope:
        exact_root = require_test_root(root)
        if type(value) is not fake_type:
            raise TrustedTimeGracefulStopV2Rejected("terminal wire is not fake-authenticated")
        try:
            envelope = value.envelope
            root_sha256 = value.root_sha256
            exact_envelope = require_root_bound_envelope(envelope, exact_root)
            exact_snapshot = snapshot(exact_envelope, root_sha256)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise TrustedTimeGracefulStopV2Rejected(
                "terminal wire is not fake-authenticated"
            ) from error
        if (
            root_sha256 != exact_root.sha256
            or require_runtime(
                value,
                snapshot_sha256=exact_snapshot,
                kind="fake_authenticated_terminal_envelope",
                provenance="test_only_fake_transport",
                scope_sha256=exact_root.sha256,
            )
            is None
        ):
            raise TrustedTimeGracefulStopV2Rejected("terminal wire is not fake-authenticated")
        return exact_envelope

    registry = LifecycleV2RuntimeSealRegistry(_seal_callers=frozenset({issue.__code__}))
    seal_runtime = registry.seal
    require_runtime = registry.require
    return issue, require


(
    _authenticate_lifecycle_v2_transport_envelope_for_tests,
    _require_fake_authenticated_lifecycle_v2_transport_envelope,
) = _build_fake_lifecycle_v2_transport_authentication_endpoints()
del _build_fake_lifecycle_v2_transport_authentication_endpoints


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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2Outcome:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("lifecycle outcomes require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _OUTCOME_FIELDS)
        if (
            fields["contract_version"] != LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["lifecycle_version"] != 2
            or type(fields["status"]) is not str
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
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2OutcomeCommit:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("lifecycle outcome commits require canonical capture")

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
            or type(fields["outcome_status"]) is not str
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
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

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
