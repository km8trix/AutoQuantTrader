"""Canonical clean-stop terminal evidence for ADR 0121 milestone one.

The values in this module are pure evidence.  They do not authenticate a
signature, publish an artifact, open a transport, or grant stop authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Self

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_CLEAN_STOP_SERVICE,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    LIFECYCLE_V2_WIRE_MAXIMUM_BYTES,
    MAXIMUM_SIGNED_INTEGER,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
    decode_lifecycle_v2_clean_stop_request,
    lifecycle_v2_wire_file_name,
)

CLEAN_STOP_RESULT_CONTRACT_VERSION = "phase6d-trusted-time-head-anchor-clean-stop-result-v2"
CLEAN_STOP_ERROR_CONTRACT_VERSION = "phase6d-trusted-time-head-anchor-clean-stop-error-v2"
SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-supervisor-transport-cleanup-commitment-v2"
)
WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-wire-envelope-publication-receipt-v2"
)
LIFECYCLE_V2_SERVICE = "trusted-time-post-enrollment-graceful-stop-lifecycle-v2"
LISTENER_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/transport/supervisor.sock"
SUPERVISOR_RAW_KEY_PATH = (
    "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets/supervisor-ed25519.raw"
)

_RESULT_MAXIMUM_BYTES = 180_224
_ERROR_MAXIMUM_BYTES = 32_768
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


def _digest(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def _domain_digest(domain: str, value: object, *, maximum_bytes: int = 256 * 1_024) -> str:
    encoded = canonical_v2_json_bytes(value, maximum_bytes=maximum_bytes)
    return hashlib.sha256(domain.encode("ascii") + b"\0" + encoded).hexdigest()


def _require_fields(value: dict[str, object], fields: frozenset[str]) -> None:
    if frozenset(value) != fields:
        raise TrustedTimeGracefulStopV2Rejected("terminal evidence field set is not exact")


def _require_text(value: object, name: str, *, maximum_bytes: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or len(value.encode("ascii")) > maximum_bytes
        or "\0" in value
    ):
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not bounded ASCII text")
    return value


def _require_sha256(value: object, name: str) -> str:
    text = _require_text(value, name, maximum_bytes=64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not lowercase SHA-256")
    return text


def _require_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAXIMUM_SIGNED_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is outside its integer bounds")
    return value


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} must be a boolean")
    return value


def _require_mapping(value: object, name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} must be an object")
    return value


def _require_path(value: object, name: str) -> str:
    path = _require_text(value, name, maximum_bytes=4_096)
    if not path.startswith("/") or "//" in path or "/./" in path or "/../" in path:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not a stable absolute path")
    return path


class _CanonicalValue:
    fields: FrozenJsonObject

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=self.maximum_bytes)

    @property
    def sha256(self) -> str:
        return _digest(self.encoded)

    @property
    def maximum_bytes(self) -> int:
        raise NotImplementedError


_TERMINAL_PROJECTION_FIELDS = frozenset(
    {
        "request_sequence",
        "request_scheduled_monotonic_ns",
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_transition_count",
        "confirmed_anchor_local_transition_ordinal",
        "predecessor_anchor_sha256",
        "current_host_head_sha256",
        "current_anchor_sha256",
        "current_anchor_semantic_sha256",
        "receipt_observed_at_utc",
        "full_audit_completed",
        "prior_pending_intent_recovered",
        "uploaded_anchor_count",
        "idempotent_duplicate_count",
        "current_anchor_intent_semantic_sha256",
        "current_candidate_remote_readback_sha256",
        "current_receipt_semantic_sha256",
        "clean_stop_terminal_result_semantic_sha256",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalProjection(_CanonicalValue):
    """The exact twenty-field clean-stop terminal projection."""

    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal projections require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _TERMINAL_PROJECTION_FIELDS)
        positive_names = (
            "request_sequence",
            "anchor_sequence",
            "confirmed_anchor_count",
            "local_transition_count",
            "confirmed_anchor_local_transition_ordinal",
        )
        for name in positive_names:
            _require_int(fields[name], name, minimum=1)
        _require_int(fields["request_scheduled_monotonic_ns"], "request_scheduled_monotonic_ns")
        anchor_sequence = _require_int(fields["anchor_sequence"], "anchor_sequence", minimum=1)
        confirmed = _require_int(
            fields["confirmed_anchor_count"], "confirmed_anchor_count", minimum=1
        )
        local_count = _require_int(
            fields["local_transition_count"], "local_transition_count", minimum=1
        )
        terminal_ordinal = _require_int(
            fields["confirmed_anchor_local_transition_ordinal"],
            "confirmed_anchor_local_transition_ordinal",
            minimum=1,
        )
        if (
            fields["checkpoint_reason"] != "clean_stop"
            or anchor_sequence != confirmed
            or anchor_sequence < 3
            or terminal_ordinal != local_count
            or local_count < anchor_sequence
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "terminal projection sequence relationship is invalid"
            )
        for name in (
            "predecessor_anchor_sha256",
            "current_host_head_sha256",
            "current_anchor_sha256",
            "current_anchor_semantic_sha256",
            "current_anchor_intent_semantic_sha256",
            "current_candidate_remote_readback_sha256",
            "current_receipt_semantic_sha256",
            "clean_stop_terminal_result_semantic_sha256",
        ):
            _require_sha256(fields[name], name)
        if fields["current_candidate_remote_readback_sha256"] != fields["current_anchor_sha256"]:
            raise TrustedTimeGracefulStopV2Rejected("terminal remote readback is not current")
        receipt_utc = _require_text(
            fields["receipt_observed_at_utc"], "receipt_observed_at_utc", maximum_bytes=27
        )
        if _UTC.fullmatch(receipt_utc) is None:
            raise TrustedTimeGracefulStopV2Rejected("receipt_observed_at_utc is not canonical UTC")
        for name in ("full_audit_completed", "prior_pending_intent_recovered"):
            _require_bool(fields[name], name)
        uploaded = _require_int(fields["uploaded_anchor_count"], "uploaded_anchor_count", maximum=1)
        duplicate = _require_int(
            fields["idempotent_duplicate_count"], "idempotent_duplicate_count", maximum=1
        )
        if uploaded + duplicate != 1:
            raise TrustedTimeGracefulStopV2Rejected(
                "terminal upload and duplicate counts do not select one result"
            )
        semantic_payload = {
            "anchor_sequence": fields["anchor_sequence"],
            "checkpoint_reason": fields["checkpoint_reason"],
            "confirmed_anchor_count": fields["confirmed_anchor_count"],
            "confirmed_anchor_local_transition_ordinal": fields[
                "confirmed_anchor_local_transition_ordinal"
            ],
            "contract_version": ("phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1"),
            "current_anchor_intent_semantic_sha256": fields[
                "current_anchor_intent_semantic_sha256"
            ],
            "current_anchor_semantic_sha256": fields["current_anchor_semantic_sha256"],
            "current_anchor_sha256": fields["current_anchor_sha256"],
            "current_candidate_remote_readback_sha256": fields[
                "current_candidate_remote_readback_sha256"
            ],
            "current_host_head_sha256": fields["current_host_head_sha256"],
            "current_receipt_semantic_sha256": fields["current_receipt_semantic_sha256"],
            "full_audit_completed": fields["full_audit_completed"],
            "idempotent_duplicate_count": fields["idempotent_duplicate_count"],
            "local_transition_count": fields["local_transition_count"],
            "predecessor_anchor_sha256": fields["predecessor_anchor_sha256"],
            "prior_pending_intent_recovered": fields["prior_pending_intent_recovered"],
            "receipt_observed_at_utc": fields["receipt_observed_at_utc"],
            "request_scheduled_monotonic_ns": fields["request_scheduled_monotonic_ns"],
            "request_sequence": fields["request_sequence"],
            "status": "exact_current_new_record_clean_stop_completed",
            "uploaded_anchor_count": fields["uploaded_anchor_count"],
        }
        semantic_sha256 = _digest(
            canonical_v2_json_bytes(semantic_payload, maximum_bytes=64 * 1_024)
        )
        if fields["clean_stop_terminal_result_semantic_sha256"] != semantic_sha256:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop terminal semantic digest disagrees")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @property
    def maximum_bytes(self) -> int:
        return _RESULT_MAXIMUM_BYTES

    @property
    def sha256(self) -> str:
        return _domain_digest(
            "AutoQuantTrader/trusted-time/graceful-stop/terminal-projection/v2",
            self.to_dict(),
            maximum_bytes=self.maximum_bytes,
        )


_CLEANUP_COMMITMENT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "admission_sha256",
        "channel_id",
        "boot_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "supervisor_container_id",
        "transport_authority_manifest_sha256",
        "key_generation",
        "supervisor_key_id",
        "supervisor_socket_identity_sha256",
        "supervisor_peer_credential_sha256",
        "listener_path",
        "listener_path_device",
        "listener_path_inode",
        "listener_fd_socket_inode",
        "accepted_fd_socket_inode",
        "raw_key_path",
        "raw_key_device",
        "raw_key_inode",
        "supervisor_challenge_sha256",
        "supervisor_process_nonce_sha256",
        "cleanup_deadline_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SupervisorCleanupCommitment(_CanonicalValue):
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("cleanup commitments require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _CLEANUP_COMMITMENT_FIELDS)
        if (
            fields["contract_version"] != SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_TRANSPORT_SERVICE
            or fields["status"] != "supervisor_transport_cleanup_committed"
            or fields["listener_path"] != LISTENER_PATH
            or fields["raw_key_path"] != SUPERVISOR_RAW_KEY_PATH
        ):
            raise TrustedTimeGracefulStopV2Rejected("cleanup commitment discriminator is invalid")
        for name in (
            "environment",
            "graceful_stop_operation_id",
            "supervisor_key_id",
        ):
            _require_text(fields[name], name)
        for name in fields:
            if name.endswith("_sha256") or name in {"channel_id", "supervisor_container_id"}:
                _require_sha256(fields[name], name)
        for name in (
            "listener_path_device",
            "listener_path_inode",
            "listener_fd_socket_inode",
            "accepted_fd_socket_inode",
            "raw_key_device",
            "raw_key_inode",
            "key_generation",
        ):
            _require_int(fields[name], name, minimum=1)
        _require_int(fields["cleanup_deadline_boottime_ns"], "cleanup_deadline_boottime_ns")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @property
    def maximum_bytes(self) -> int:
        return _RESULT_MAXIMUM_BYTES

    @property
    def sha256(self) -> str:
        return _domain_digest(
            "AutoQuantTrader/trusted-time/graceful-stop/supervisor-transport-cleanup-commitment/v2",
            self.to_dict(),
            maximum_bytes=self.maximum_bytes,
        )


_RESULT_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "admission_sha256",
        "lifecycle_dispatch_prefix_sha256",
        "channel_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "supervisor_container_id",
        "operation_bound_request",
        "request_sha256",
        "terminal_projection",
        "terminal_projection_sha256",
        "supervisor_transport_cleanup_commitment",
        "supervisor_transport_cleanup_commitment_sha256",
        "result_completed_boottime_ns",
        "transport_cleanup_deadline_boottime_ns",
        "operation_deadline_boottime_ns",
    }
)


def _require_request_correlators(
    fields: dict[str, object],
    request: LifecycleV2CleanStopRequest,
) -> dict[str, object]:
    request_fields = request.to_dict()
    pairs = {
        "environment": "environment",
        "graceful_stop_operation_id": "graceful_stop_operation_id",
        "lifecycle_root_sha256": "lifecycle_root_sha256",
        "admission_sha256": "admission_sha256",
        "lifecycle_dispatch_prefix_sha256": "lifecycle_dispatch_prefix_sha256",
        "channel_id": "channel_id",
        "boot_epoch_sha256": "boot_epoch_sha256",
        "host_process_epoch_sha256": "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256": "supervisor_process_epoch_sha256",
        "supervisor_container_id": "supervisor_container_id",
        "transport_cleanup_deadline_boottime_ns": "transport_cleanup_deadline_boottime_ns",
        "operation_deadline_boottime_ns": "operation_deadline_boottime_ns",
    }
    if any(fields[left] != request_fields[right] for left, right in pairs.items()):
        raise TrustedTimeGracefulStopV2Rejected("terminal payload is cross-request")
    if fields["request_sha256"] != request.sha256:
        raise TrustedTimeGracefulStopV2Rejected("terminal request digest disagrees")
    return request_fields


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2CleanStopResult(_CanonicalValue):
    fields: FrozenJsonObject
    request: LifecycleV2CleanStopRequest
    terminal_projection: LifecycleV2TerminalProjection
    cleanup_commitment: LifecycleV2SupervisorCleanupCommitment

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("clean-stop results require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _RESULT_FIELDS)
        if (
            fields["contract_version"] != CLEAN_STOP_RESULT_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_CLEAN_STOP_SERVICE
            or fields["status"]
            != "exact_operation_bound_new_record_clean_stop_correlated_unqualified"
        ):
            raise TrustedTimeGracefulStopV2Rejected("clean-stop result discriminator is invalid")
        request_value = _require_mapping(
            fields["operation_bound_request"], "operation_bound_request"
        )
        request = decode_lifecycle_v2_clean_stop_request(
            canonical_v2_json_bytes(request_value, maximum_bytes=64 * 1_024)
        )
        request_fields = _require_request_correlators(fields, request)
        projection = LifecycleV2TerminalProjection.capture(fields["terminal_projection"])
        if fields["terminal_projection_sha256"] != projection.sha256:
            raise TrustedTimeGracefulStopV2Rejected("terminal projection digest disagrees")
        cleanup = LifecycleV2SupervisorCleanupCommitment.capture(
            fields["supervisor_transport_cleanup_commitment"]
        )
        if fields["supervisor_transport_cleanup_commitment_sha256"] != cleanup.sha256:
            raise TrustedTimeGracefulStopV2Rejected("cleanup commitment digest disagrees")
        cleanup_fields = cleanup.to_dict()
        for name in (
            "environment",
            "graceful_stop_operation_id",
            "lifecycle_root_sha256",
            "admission_sha256",
            "channel_id",
            "boot_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "supervisor_container_id",
        ):
            if cleanup_fields[name] != fields[name]:
                raise TrustedTimeGracefulStopV2Rejected("cleanup commitment is cross-result")
        if (
            cleanup_fields["cleanup_deadline_boottime_ns"]
            != fields["transport_cleanup_deadline_boottime_ns"]
        ):
            raise TrustedTimeGracefulStopV2Rejected("cleanup deadline disagrees")
        completed = _require_int(
            fields["result_completed_boottime_ns"], "result_completed_boottime_ns"
        )
        result_deadline = _require_int(
            request_fields["clean_stop_result_deadline_boottime_ns"],
            "clean_stop_result_deadline_boottime_ns",
        )
        operation_deadline = _require_int(
            fields["operation_deadline_boottime_ns"], "operation_deadline_boottime_ns"
        )
        cleanup_deadline = _require_int(
            fields["transport_cleanup_deadline_boottime_ns"],
            "transport_cleanup_deadline_boottime_ns",
        )
        if not completed < result_deadline or not completed < operation_deadline:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop result is late")
        if not completed < cleanup_deadline <= operation_deadline:
            raise TrustedTimeGracefulStopV2Rejected("cleanup commitment is not future-bounded")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "request", request)
        object.__setattr__(result, "terminal_projection", projection)
        object.__setattr__(result, "cleanup_commitment", cleanup)
        if len(result.encoded) > _RESULT_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop result exceeds its bound")
        return result

    @property
    def maximum_bytes(self) -> int:
        return _RESULT_MAXIMUM_BYTES


_ERROR_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "request_sha256",
        "admission_sha256",
        "lifecycle_dispatch_prefix_sha256",
        "channel_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "supervisor_container_id",
        "error_code",
        "failure_boundary",
        "call_may_have_occurred",
        "retryable",
        "observed_boottime_ns",
        "supervisor_transport_cleanup_commitment",
        "supervisor_transport_cleanup_commitment_sha256",
        "transport_cleanup_deadline_boottime_ns",
        "operation_deadline_boottime_ns",
    }
)
_ERROR_CODES = frozenset(
    {
        "request_expired",
        "worker_busy",
        "selection_failed",
        "clean_stop_failed",
        "result_unavailable",
    }
)
_FAILURE_BOUNDARIES = frozenset({"before_selection", "during_or_after_selection", "unknown"})


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2CleanStopError(_CanonicalValue):
    fields: FrozenJsonObject
    request: LifecycleV2CleanStopRequest
    cleanup_commitment: LifecycleV2SupervisorCleanupCommitment

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("clean-stop errors require request-bound canonical capture")

    @classmethod
    def capture(cls, value: object, *, request: LifecycleV2CleanStopRequest) -> Self:
        if type(request) is not LifecycleV2CleanStopRequest:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop error requires an exact request")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _ERROR_FIELDS)
        if (
            fields["contract_version"] != CLEAN_STOP_ERROR_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_CLEAN_STOP_SERVICE
            or fields["status"] != "operation_bound_clean_stop_failed_unqualified"
            or fields["error_code"] not in _ERROR_CODES
            or fields["failure_boundary"] not in _FAILURE_BOUNDARIES
            or fields["retryable"] is not False
        ):
            raise TrustedTimeGracefulStopV2Rejected("clean-stop error discriminator is invalid")
        request_fields = _require_request_correlators(fields, request)
        _require_bool(fields["call_may_have_occurred"], "call_may_have_occurred")
        cleanup = LifecycleV2SupervisorCleanupCommitment.capture(
            fields["supervisor_transport_cleanup_commitment"]
        )
        if fields["supervisor_transport_cleanup_commitment_sha256"] != cleanup.sha256:
            raise TrustedTimeGracefulStopV2Rejected("cleanup commitment digest disagrees")
        cleanup_fields = cleanup.to_dict()
        for name in (
            "environment",
            "graceful_stop_operation_id",
            "lifecycle_root_sha256",
            "admission_sha256",
            "channel_id",
            "boot_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "supervisor_container_id",
        ):
            if cleanup_fields[name] != fields[name]:
                raise TrustedTimeGracefulStopV2Rejected("cleanup commitment is cross-error")
        cleanup_deadline = _require_int(
            fields["transport_cleanup_deadline_boottime_ns"],
            "transport_cleanup_deadline_boottime_ns",
        )
        if (
            cleanup_fields["cleanup_deadline_boottime_ns"] != cleanup_deadline
            or cleanup_deadline != request_fields["transport_cleanup_deadline_boottime_ns"]
        ):
            raise TrustedTimeGracefulStopV2Rejected("cleanup deadline disagrees")
        observed = _require_int(fields["observed_boottime_ns"], "observed_boottime_ns")
        operation_deadline = _require_int(
            fields["operation_deadline_boottime_ns"], "operation_deadline_boottime_ns"
        )
        if observed >= operation_deadline:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop error observation is late")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "request", request)
        object.__setattr__(result, "cleanup_commitment", cleanup)
        if len(result.encoded) > _ERROR_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("clean-stop error exceeds its bound")
        return result

    @property
    def maximum_bytes(self) -> int:
        return _ERROR_MAXIMUM_BYTES


_PUBLICATION_RECEIPT_FIELDS = frozenset(
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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2WirePublicationReceipt(_CanonicalValue):
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("wire publication receipts require canonical capture")

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        request: LifecycleV2CleanStopRequest,
        root_sha256: str,
    ) -> Self:
        if type(envelope) is not UnverifiedLifecycleV2TransportEnvelope:
            raise TrustedTimeGracefulStopV2Rejected("publication requires an exact envelope")
        terminal = validate_terminal_envelope_payload(envelope, request=request)
        request_fields = request.to_dict()
        _require_sha256(root_sha256, "root_sha256")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _PUBLICATION_RECEIPT_FIELDS)
        envelope_fields = envelope.to_dict()
        frame_type = envelope.frame_type
        expected_kind = {
            "clean_stop_result": "signed_result_envelope",
            "clean_stop_error": "signed_error_envelope",
        }.get(frame_type)
        if expected_kind is None:
            raise TrustedTimeGracefulStopV2Rejected("request envelopes cannot be published")
        directory = _require_path(fields["artifact_directory_path"], "artifact_directory_path")
        file_name = lifecycle_v2_wire_file_name(envelope)
        if (
            fields["contract_version"] != WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["status"] != "wire_envelope_published"
            or fields["environment"] != request_fields["environment"]
            or fields["graceful_stop_operation_id"] != request_fields["graceful_stop_operation_id"]
            or fields["root_sha256"] != root_sha256
            or fields["artifact_kind"] != expected_kind
            or fields["artifact_path"] != f"{directory}/{file_name}"
            or fields["file_name"] != file_name
            or fields["file_mode"] != 384
            or fields["file_size"] != len(envelope.encoded)
            or fields["signed_envelope_sha256"] != envelope.sha256
            or fields["envelope_contract_version"]
            != LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION
            or fields["frame_type"] != frame_type
            or fields["payload_contract_version"] != envelope_fields["payload_contract_version"]
            or fields["payload_sha256"] != envelope_fields["payload_sha256"]
            or fields["signature_sha256"] != envelope.signature_sha256
            or fields["key_generation"] != envelope_fields["key_generation"]
            or fields["signing_key_id"] != envelope_fields["signing_key_id"]
            or fields["channel_id"] != envelope_fields["channel_id"]
            or fields["lifecycle_dispatch_prefix_sha256"]
            != envelope_fields["lifecycle_dispatch_prefix_sha256"]
            or fields["message_counter"] != envelope_fields["message_counter"]
            or fields["deadline_boottime_ns"] != envelope_fields["deadline_boottime_ns"]
            or fields["directory_fsync_completed"] is not True
            or fields["stable_readback_completed"] is not True
        ):
            raise TrustedTimeGracefulStopV2Rejected("publication receipt disagrees with wire")
        for name in (
            "artifact_directory_device",
            "artifact_directory_inode",
            "file_device",
            "file_inode",
            "file_size",
            "key_generation",
            "message_counter",
        ):
            _require_int(fields[name], name, minimum=1)
        for name in (
            "root_sha256",
            "signed_envelope_sha256",
            "payload_sha256",
            "signature_sha256",
            "channel_id",
            "lifecycle_dispatch_prefix_sha256",
        ):
            _require_sha256(fields[name], name)
        authorized = _require_int(
            fields["publication_authorized_boottime_ns"],
            "publication_authorized_boottime_ns",
        )
        deadline = _require_int(fields["deadline_boottime_ns"], "deadline_boottime_ns")
        if authorized >= deadline:
            raise TrustedTimeGracefulStopV2Rejected("wire publication authorization expired")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        if terminal.to_dict()["lifecycle_root_sha256"] != root_sha256:
            raise TrustedTimeGracefulStopV2Rejected(
                "published terminal payload does not bind the lifecycle root"
            )
        return result

    @property
    def maximum_bytes(self) -> int:
        return LIFECYCLE_V2_WIRE_MAXIMUM_BYTES

    @property
    def sha256(self) -> str:
        return _domain_digest(
            "AutoQuantTrader/trusted-time/graceful-stop/wire-envelope-publication-receipt/v2",
            self.to_dict(),
            maximum_bytes=self.maximum_bytes,
        )


def decode_lifecycle_v2_clean_stop_result(encoded: object) -> LifecycleV2CleanStopResult:
    return LifecycleV2CleanStopResult.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=_RESULT_MAXIMUM_BYTES)
    )


def decode_lifecycle_v2_clean_stop_error(
    encoded: object,
    *,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2CleanStopError:
    return LifecycleV2CleanStopError.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=_ERROR_MAXIMUM_BYTES),
        request=request,
    )


def lifecycle_v2_wire_publication_receipt_sha256(
    receipt: LifecycleV2WirePublicationReceipt,
) -> str:
    if type(receipt) is not LifecycleV2WirePublicationReceipt:
        raise TrustedTimeGracefulStopV2Rejected("publication receipt type is not exact")
    return receipt.sha256


_RESULT_WIRE_EVIDENCE_FIELDS = frozenset(
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
_ERROR_WIRE_EVIDENCE_FIELDS = frozenset(
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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalWireEvidence(_CanonicalValue):
    """The exact typed ordinal-two evidence bound to full terminal wire bytes."""

    fields: FrozenJsonObject
    receipt: LifecycleV2WirePublicationReceipt

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal wire evidence requires request-bound canonical capture")

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        request: LifecycleV2CleanStopRequest,
        root_sha256: str,
        responder_identity_sha256: str,
    ) -> Self:
        if (
            type(envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or type(request) is not LifecycleV2CleanStopRequest
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "terminal wire evidence inputs are not exact types"
            )
        terminal = validate_terminal_envelope_payload(envelope, request=request)
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        is_result = envelope.frame_type == "clean_stop_result"
        _require_fields(
            fields,
            _RESULT_WIRE_EVIDENCE_FIELDS if is_result else _ERROR_WIRE_EVIDENCE_FIELDS,
        )
        prefix = "clean_stop_result" if is_result else "clean_stop_error"
        expected_disposition = "authenticated_result" if is_result else "authenticated_error"
        envelope_fields = envelope.to_dict()
        artifact_name = lifecycle_v2_wire_file_name(envelope)
        receipt = LifecycleV2WirePublicationReceipt.capture(
            fields["wire_publication_receipt"],
            envelope=envelope,
            request=request,
            root_sha256=root_sha256,
        )
        receipt_fields = receipt.to_dict()
        if (
            fields["intent_sha256"] != request.to_dict()["request_intent_sha256"]
            or fields["responder_identity_sha256"] != responder_identity_sha256
            or fields["disposition"] != expected_disposition
            or fields[f"{prefix}_artifact_path"] != receipt_fields["artifact_path"]
            or fields[f"{prefix}_artifact_name"] != artifact_name
            or fields[f"{prefix}_sha256"] != envelope.sha256
            or fields["envelope_contract_version"]
            != LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION
            or fields["frame_type"] != envelope.frame_type
            or fields["payload_contract_version"] != envelope_fields["payload_contract_version"]
            or fields[f"{prefix}_payload_sha256"] != envelope_fields["payload_sha256"]
            or fields[f"{prefix}_signature_sha256"] != envelope.signature_sha256
            or fields["key_generation"] != envelope_fields["key_generation"]
            or fields["signing_key_id"] != envelope_fields["signing_key_id"]
            or fields["channel_id"] != envelope_fields["channel_id"]
            or fields["lifecycle_dispatch_prefix_sha256"]
            != envelope_fields["lifecycle_dispatch_prefix_sha256"]
            or fields["message_counter"] != 1
            or fields["deadline_boottime_ns"] != envelope_fields["deadline_boottime_ns"]
            or fields["wire_publication_receipt_sha256"] != receipt.sha256
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "ordinal-two evidence disagrees with the terminal wire"
            )
        _require_sha256(responder_identity_sha256, "responder_identity_sha256")
        if is_result:
            if type(terminal) is not LifecycleV2CleanStopResult:
                raise TrustedTimeGracefulStopV2Rejected("result frame decoded as another type")
            if fields["terminal_projection_sha256"] != terminal.terminal_projection.sha256:
                raise TrustedTimeGracefulStopV2Rejected(
                    "ordinal-two terminal projection digest disagrees"
                )
        else:
            if type(terminal) is not LifecycleV2CleanStopError:
                raise TrustedTimeGracefulStopV2Rejected("error frame decoded as another type")
            terminal_fields = terminal.to_dict()
            if (
                fields["error_code"] != terminal_fields["error_code"]
                or fields["failure_boundary"] != terminal_fields["failure_boundary"]
            ):
                raise TrustedTimeGracefulStopV2Rejected("ordinal-two error diagnostic disagrees")
        started = _require_int(fields["call_started_boottime_ns"], "call_started_boottime_ns")
        completed = _require_int(fields["call_completed_boottime_ns"], "call_completed_boottime_ns")
        authorized = _require_int(
            receipt_fields["publication_authorized_boottime_ns"],
            "publication_authorized_boottime_ns",
        )
        deadline = _require_int(fields["deadline_boottime_ns"], "deadline_boottime_ns")
        if not started <= completed <= authorized < deadline:
            raise TrustedTimeGracefulStopV2Rejected(
                "ordinal-two call and publication timestamps are not ordered"
            )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "receipt", receipt)
        return result

    @property
    def maximum_bytes(self) -> int:
        return 256 * 1_024

    @property
    def sha256(self) -> str:
        return _digest(self.encoded)


def validate_terminal_envelope_payload(
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    *,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2CleanStopResult | LifecycleV2CleanStopError:
    """Decode one structurally verified terminal payload against its exact request."""

    if type(envelope) is not UnverifiedLifecycleV2TransportEnvelope:
        raise TrustedTimeGracefulStopV2Rejected("terminal envelope type is not exact")
    if envelope.frame_type == "clean_stop_result":
        return decode_lifecycle_v2_clean_stop_result(envelope.payload)
    if envelope.frame_type == "clean_stop_error":
        return decode_lifecycle_v2_clean_stop_error(envelope.payload, request=request)
    raise TrustedTimeGracefulStopV2Rejected("request envelope is not terminal evidence")


def terminal_non_authority_facts() -> dict[str, bool]:
    return {
        "signature_verifier_present": False,
        "artifact_publisher_present": False,
        "transport_present": False,
        "docker_effect_present": False,
        "production_caller_present": False,
    }


__all__ = [
    "CLEAN_STOP_ERROR_CONTRACT_VERSION",
    "CLEAN_STOP_RESULT_CONTRACT_VERSION",
    "SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION",
    "WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION",
    "LifecycleV2CleanStopError",
    "LifecycleV2CleanStopResult",
    "LifecycleV2SupervisorCleanupCommitment",
    "LifecycleV2TerminalProjection",
    "LifecycleV2TerminalWireEvidence",
    "LifecycleV2WirePublicationReceipt",
    "decode_lifecycle_v2_clean_stop_error",
    "decode_lifecycle_v2_clean_stop_result",
    "lifecycle_v2_wire_publication_receipt_sha256",
    "terminal_non_authority_facts",
    "validate_terminal_envelope_payload",
]
