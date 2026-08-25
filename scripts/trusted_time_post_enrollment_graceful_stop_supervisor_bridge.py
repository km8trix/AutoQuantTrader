"""Inert host binding for one operation-bound graceful-stop terminal projection.

The request builder owns ADR-0112 pending-receipt authentication and immediate
consuming revalidation, then binds the source-derived immutable receipt
projection to the exact request identity and the publicly revalidated ADR-0110
attempt/progress chain.  The scalar receipt digest remains structural on the
wire; only the private process-local association authenticates its source.

The terminal binder consumes one exact ADR-0109 postcondition before it
performs the remaining structural checks.  A mismatch therefore burns that
postcondition.  The resulting process-local composite proves only that the
ADR-0108 and ADR-0109 terminal projections were exactly cross-bound; decoded
ADR-0111 wire evidence does not authenticate its transport or supervisor
origin.  Nothing here sends a signal, performs SQL/provider work, mutates the
lifecycle repository, or grants a shutdown or teardown action.
"""

from __future__ import annotations

import builtins as _BUILTINS
import hashlib
import json
import os
import threading
import uuid
import weakref
from builtins import property as _EVIDENCE_PROPERTY
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-supervisor-bridge-v2"
)
POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-supervisor-bridge"
)
POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS = (
    "receipt_authenticated_operation_bound_terminal_projection_cross_bound_unqualified"
)

_ORIGIN_PID = os.getpid()
_PATH_TYPE = type(Path())

_REQUEST_BINDING_FIELDS = (
    "graceful_stop_operation_id",
    "graceful_stop_target_sha256",
    "graceful_stop_decision_v1_sha256",
    "graceful_stop_decision_artifact_receipt_sha256",
    "operator_attestation_envelope_sha256",
    "attempt_slot_sha256",
    "bridge_required_progress_sha256",
    "controller_outcome_sha256",
    "durable_shutdown_locator_sha256",
    "active_controller_session_sha256",
    "persistent_topology_sha256",
    "persistent_topology_transcript_sha256",
    "supervisor_container_id",
)

_RESULT_TERMINAL_FIELDS = (
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
)

_REAUTHENTICATION_BINDING_FIELDS = (
    "remote_object_count",
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
)

_DECISION_RECEIPT_IDENTITY_FIELDS = (
    "artifact_location",
    "controller_outcome_sha256",
    "durable_shutdown_locator_sha256",
    "graceful_stop_decision_v1_sha256",
    "graceful_stop_operation_id",
    "graceful_stop_target_sha256",
    "start_approval_sha256",
    "start_approved_image_provenance_sha256",
    "start_approved_image_provenance_source_revision_sha256",
    "start_execution_attempt_slot_sha256",
    "start_git_revision",
    "start_operation_id",
    "start_operator_attestation_envelope_sha256",
    "start_source_image_id",
    "start_supervisor_image_id",
)

_DECISION_RECEIPT_TRUE_FACT_FIELDS = frozenset(
    {
        "committed_confirmed_start_outcome_revalidated",
        "decision_candidate_semantically_bound",
        "durable_shutdown_locator_revalidated",
        "external_stop_attestation_required",
        "historical_evidence_only",
        "historical_start_chain_authenticated",
        "later_atomic_stop_admission_revalidation_required",
        "start_execution_attempt_slot_revalidated",
        "start_operator_attestation_envelope_revalidated",
        "verification_only",
    }
)
_DECISION_RECEIPT_FALSE_QUALIFICATION_FIELDS = frozenset(
    {
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "stop_admission_qualified",
        "stop_attempt_slot_reserved",
        "stop_effect_authorized",
        "stop_operator_signature_authenticated",
        "stop_outcome_or_recovery_available",
    }
)

_POSTCONDITION_SNAPSHOT_FIELDS = (
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
)

_COMPOSITE_FIELDS = (
    *_REQUEST_BINDING_FIELDS,
    "operation_bound_request_sha256",
    "operation_bound_result_sha256",
    *_RESULT_TERMINAL_FIELDS,
    *_REAUTHENTICATION_BINDING_FIELDS,
    "terminal_reauthentication_semantic_sha256",
)

_CLOSED_FIELDS = frozenset(
    {
        "active_controller_authorized",
        "admission_authorized",
        "alert_delivery_authorized",
        "arming_authorized",
        "authority_granted",
        "automatic_rearm_authorized",
        "automatic_recovery_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "claim_retention_authorized",
        "clean_stop_authorized",
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "container_removal_authorized",
        "controller_execution_authorized",
        "current_topology_authenticated",
        "currentness_authenticated",
        "currentness_qualified",
        "database_secret_disclosed",
        "decision_authenticated",
        "durability_authenticated",
        "durable",
        "durable_stop_outcome_authenticated",
        "effect_authorized",
        "exact_request_work_result_correlated",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "exposure_authorized",
        "freshness_authenticated",
        "freshness_qualified",
        "graceful_stop_authorized",
        "lifecycle_currentness_authenticated",
        "live_trading_authorized",
        "network_removal_authorized",
        "new_exposure_authorized",
        "no_new_record_authenticated",
        "no_new_record_success",
        "operation_bound_supervisor_bridge_authenticated",
        "operational_control_authorized",
        "operator_attestation_authenticated",
        "outcome_retention_authorized",
        "paper_trading_authorized",
        "persistent_start_authorized",
        "persistent_topology_authenticated",
        "qualified",
        "readiness_authorized",
        "rearm_authorized",
        "recovery_action_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "signal_attempted",
        "signal_authorized",
        "single_use_authenticated",
        "slot_authorized",
        "source_start_authorized",
        "source_stop_authorized",
        "start_execution_attempt_authenticated",
        "stop_admission_qualified",
        "stop_attempt_reservation_authorized",
        "stop_attempt_slot_reserved",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "stop_outcome_retained",
        "success_outcome_retention_authorized",
        "supervisor_signal_authorized",
        "supervisor_start_authorized",
        "supervisor_stop_authorized",
        "target_authenticated",
        "teardown_authenticated",
        "teardown_authorized",
        "terminal_outcome_success_confirmed",
        "topology_mutation_authorized",
        "transport_authenticated",
        "transport_origin_authenticated",
        "volume_removal_authorized",
        "watchdog_authorized",
    }
)


class TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(RuntimeError):
    """The host could not form one exact inert terminal composition."""


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
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _closed_payload() -> dict[str, object]:
    return {name: False for name in _CLOSED_FIELDS}


def _cannot_copy() -> Never:
    raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
        "trusted-time graceful-stop supervisor bridge evidence cannot be copied or serialized"
    )


class _ClosedHostBridgeEvidence:
    active_controller_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    admission_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    alert_delivery_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    arming_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    authority_granted = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_rearm_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_recovery_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_resume_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    broker_action_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    claim_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    clean_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    clean_stop_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    confirmed_start_outcome_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    container_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    controller_execution_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    current_topology_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    currentness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    currentness_qualified = _EVIDENCE_PROPERTY(lambda _: False)
    database_secret_disclosed = _EVIDENCE_PROPERTY(lambda _: False)
    decision_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    durability_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    durable = _EVIDENCE_PROPERTY(lambda _: False)
    durable_stop_outcome_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    effect_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    exact_request_work_result_correlated = _EVIDENCE_PROPERTY(lambda _: False)
    execution_admission_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    execution_attempt_reservation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    exposure_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    freshness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    freshness_qualified = _EVIDENCE_PROPERTY(lambda _: False)
    graceful_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    lifecycle_currentness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    live_trading_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    network_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    new_exposure_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    no_new_record_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    no_new_record_success = _EVIDENCE_PROPERTY(lambda _: False)
    operation_bound_supervisor_bridge_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    operational_control_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    operator_attestation_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    paper_trading_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    persistent_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    persistent_topology_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    qualified = _EVIDENCE_PROPERTY(lambda _: False)
    readiness_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    rearm_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    recovery_action_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    release_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    retry_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    runtime_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    sequence_2_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_locator_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    signal_attempted = _EVIDENCE_PROPERTY(lambda _: False)
    signal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    single_use_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    slot_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    source_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    source_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    start_execution_attempt_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    stop_admission_qualified = _EVIDENCE_PROPERTY(lambda _: False)
    stop_attempt_reservation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    stop_attempt_slot_reserved = _EVIDENCE_PROPERTY(lambda _: False)
    stop_decision_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    stop_execution_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    stop_outcome_retained = _EVIDENCE_PROPERTY(lambda _: False)
    success_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_signal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    target_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    teardown_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    teardown_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    terminal_outcome_success_confirmed = _EVIDENCE_PROPERTY(lambda _: False)
    topology_mutation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    transport_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    transport_origin_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    volume_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    watchdog_authorized = _EVIDENCE_PROPERTY(lambda _: False)


class _BridgeIdentity:
    __slots__ = ()

    def __new__(cls) -> _BridgeIdentity:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor bridge identity is private"
        )


def _new_bridge_identity() -> _BridgeIdentity:
    return cast(_BridgeIdentity, object.__new__(cast(type[Any], _BridgeIdentity)))


def _exact_roots(
    artifact_directory: object,
    *,
    ignored_root: object,
) -> tuple[Path, Path]:
    if type(artifact_directory) is not _PATH_TYPE or type(ignored_root) is not _PATH_TYPE:
        raise ValueError
    exact_directory = artifact_directory
    exact_root = ignored_root
    if (
        not exact_directory.is_absolute()
        or exact_directory != Path(os.path.abspath(exact_directory))
        or not exact_root.is_absolute()
        or exact_root != Path(os.path.abspath(exact_root))
        or exact_directory != exact_root / "trusted-time"
    ):
        raise ValueError
    return exact_directory, exact_root


@dataclass(frozen=True, slots=True)
class _DecisionReceiptSnapshot:
    loaded_identity: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    bridge_identity: _BridgeIdentity
    consumed_identity: _ConsumedLoadedDecisionArtifactReceiptSnapshot
    values: tuple[object, ...]
    encoded: bytes
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _AttemptSnapshot:
    identity: RetainedTrustedTimePostEnrollmentGracefulStopAttempt
    record_identity: object
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _ProgressSnapshot:
    identity: RetainedTrustedTimePostEnrollmentGracefulStopProgress
    record_identity: object
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]
    attempt_slot_file_identity: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _RequestEvidenceSnapshot:
    receipt: _DecisionReceiptSnapshot
    attempt: _AttemptSnapshot
    progress: _ProgressSnapshot


@dataclass(frozen=True, slots=True)
class _RequestWireSnapshot:
    encoded: bytes
    values: tuple[object, ...]
    request_sha256: str


@dataclass(frozen=True, slots=True)
class _ResultWireSnapshot:
    encoded: bytes
    request: _RequestWireSnapshot
    values: tuple[object, ...]
    result_sha256: str


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError
        result[key] = item
    return result


def _reject_json_number(_: str) -> Never:
    raise ValueError


def _decode_receipt_identity_values(encoded: object) -> tuple[object, ...]:
    if type(encoded) is not bytes or not encoded or len(encoded) > 128 * 1_024:
        raise ValueError
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_number,
            parse_float=_reject_json_number,
            parse_int=_reject_json_number,
        )
        canonical = canonical_first_enrollment_json_bytes(payload)
    except (
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        TrustedTimeEnrollmentEvidenceError,
    ):
        raise ValueError from None
    if (
        type(payload) is not dict
        or set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS
        or canonical != encoded
        or any(type(item) not in {str, bool} for item in payload.values())
        or any(type(payload.get(name)) is not str for name in _DECISION_RECEIPT_IDENTITY_FIELDS)
    ):
        raise ValueError
    exact_payload = cast(dict[str, object], payload)
    identity_values = tuple(exact_payload[name] for name in _DECISION_RECEIPT_IDENTITY_FIELDS)
    expected_payload: dict[str, object] = {
        name: False for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    }
    expected_payload.update({name: True for name in _DECISION_RECEIPT_TRUE_FACT_FIELDS})
    expected_payload.update({name: False for name in _DECISION_RECEIPT_FALSE_QUALIFICATION_FIELDS})
    expected_payload.update(
        dict(
            zip(
                _DECISION_RECEIPT_IDENTITY_FIELDS,
                identity_values,
                strict=True,
            )
        )
    )
    expected_payload.update(
        {
            "contract_version": ARTIFACT_RECEIPT_CONTRACT_VERSION,
            "service": ARTIFACT_WORKFLOW_SERVICE,
            "status": DECISION_CANDIDATE_PREPARED_STATUS,
        }
    )
    if (
        set(expected_payload) != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS
        or exact_payload != expected_payload
        or canonical_first_enrollment_json_bytes(expected_payload) != encoded
    ):
        raise ValueError
    return identity_values


def _decode_request_wire_snapshot(encoded: object) -> _RequestWireSnapshot:
    if type(encoded) is not bytes:
        raise ValueError
    decoded = decode_trusted_time_head_anchor_operation_bound_clean_stop_request(encoded)
    values = tuple(getattr(decoded, name) for name in _REQUEST_BINDING_FIELDS)
    return _RequestWireSnapshot(
        encoded=encoded,
        values=values,
        request_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _capture_request_wire_snapshot(value: object) -> _RequestWireSnapshot:
    if type(value) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
        raise ValueError
    encoded = canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes(value)
    snapshot = _decode_request_wire_snapshot(encoded)
    value.__post_init__()
    if tuple(getattr(value, name) for name in _REQUEST_BINDING_FIELDS) != snapshot.values:
        raise ValueError
    return snapshot


def _decode_result_wire_snapshot(encoded: object) -> _ResultWireSnapshot:
    if type(encoded) is not bytes:
        raise ValueError
    decoded = decode_trusted_time_head_anchor_operation_bound_clean_stop_result(encoded)
    decoded_request = decoded.request
    request_encoded = canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes(
        decoded_request
    )
    request = _decode_request_wire_snapshot(request_encoded)
    values = tuple(getattr(decoded, name) for name in _RESULT_TERMINAL_FIELDS)
    return _ResultWireSnapshot(
        encoded=encoded,
        request=request,
        values=values,
        result_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _capture_result_wire_snapshot(value: object) -> _ResultWireSnapshot:
    if type(value) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult:
        raise ValueError
    encoded = canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(value)
    snapshot = _decode_result_wire_snapshot(encoded)
    value.__post_init__()
    if (
        tuple(getattr(value, name) for name in _RESULT_TERMINAL_FIELDS) != snapshot.values
        or _capture_request_wire_snapshot(value.request) != snapshot.request
    ):
        raise ValueError
    return snapshot


def _require_consumed_postcondition_snapshot(
    snapshot: object,
    *,
    issuer: object,
    bridge_identity: object,
) -> _ConsumedPostconditionRegistrySnapshot:
    if (
        type(snapshot) is not _ConsumedPostconditionRegistrySnapshot
        or type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
        or type(bridge_identity) is not _BridgeIdentity
    ):
        raise ValueError
    exact = snapshot
    exact.__post_init__()
    if exact.issuer_identity is not issuer or exact.bridge_identity is not bridge_identity:
        raise ValueError
    return exact


def _same_consumed_postcondition_snapshot(
    left: _ConsumedPostconditionRegistrySnapshot,
    right: _ConsumedPostconditionRegistrySnapshot,
) -> bool:
    return (
        left.values == right.values
        and left.semantic_sha256 == right.semantic_sha256
        and left.issuer_identity is right.issuer_identity
        and left.bridge_identity is right.bridge_identity
    )


def _capture_consumed_receipt_snapshot(
    value: object,
    *,
    loaded_identity: object,
    bridge_identity: object,
) -> _DecisionReceiptSnapshot:
    if (
        type(loaded_identity)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(bridge_identity) is not _BridgeIdentity
    ):
        raise ValueError
    consumed = _require_consumed_loaded_decision_artifact_receipt_snapshot(
        value,
        loaded_identity=loaded_identity,
        consumer_identity=bridge_identity,
    )
    encoded = consumed.receipt_encoded
    values = _decode_receipt_identity_values(encoded)
    if (
        values != consumed.receipt_identity_values
        or not _is_sha256(consumed.receipt_sha256)
        or hashlib.sha256(encoded).hexdigest() != consumed.receipt_sha256
    ):
        raise ValueError
    return _DecisionReceiptSnapshot(
        loaded_identity=loaded_identity,
        bridge_identity=bridge_identity,
        consumed_identity=consumed,
        values=values,
        encoded=encoded,
        receipt_sha256=consumed.receipt_sha256,
    )


def _require_consumed_receipt_snapshot_current(
    snapshot: _DecisionReceiptSnapshot,
) -> None:
    if (
        type(snapshot) is not _DecisionReceiptSnapshot
        or type(snapshot.loaded_identity)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(snapshot.bridge_identity) is not _BridgeIdentity
        or _require_consumed_loaded_decision_artifact_receipt_snapshot(
            snapshot.consumed_identity,
            loaded_identity=snapshot.loaded_identity,
            consumer_identity=snapshot.bridge_identity,
        )
        is not snapshot.consumed_identity
        or _decode_receipt_identity_values(snapshot.encoded) != snapshot.values
        or snapshot.values != snapshot.consumed_identity.receipt_identity_values
        or snapshot.encoded != snapshot.consumed_identity.receipt_encoded
        or snapshot.receipt_sha256 != snapshot.consumed_identity.receipt_sha256
        or hashlib.sha256(snapshot.encoded).hexdigest() != snapshot.receipt_sha256
    ):
        raise ValueError


def _capture_attempt_snapshot(value: object) -> _AttemptSnapshot:
    if type(value) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
        raise ValueError
    value.__post_init__()
    return _AttemptSnapshot(
        identity=value,
        record_identity=value.record,
        artifact_sha256=value.artifact_sha256,
        artifact_path=value.artifact_path,
        encoded=value.encoded,
        file_identity=value.file_identity,
    )


def _capture_progress_snapshot(value: object) -> _ProgressSnapshot:
    if type(value) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress:
        raise ValueError
    value.__post_init__()
    return _ProgressSnapshot(
        identity=value,
        record_identity=value.record,
        artifact_sha256=value.artifact_sha256,
        artifact_path=value.artifact_path,
        encoded=value.encoded,
        file_identity=value.file_identity,
        attempt_slot_file_identity=value.attempt_slot_file_identity,
    )


def _capture_request_evidence_snapshot(
    *,
    decision_artifact_receipt: object,
    retained_attempt: object,
    retained_progress: object,
) -> _RequestEvidenceSnapshot:
    if type(decision_artifact_receipt) is not _DecisionReceiptSnapshot:
        raise ValueError
    _require_consumed_receipt_snapshot_current(decision_artifact_receipt)
    return _RequestEvidenceSnapshot(
        receipt=decision_artifact_receipt,
        attempt=_capture_attempt_snapshot(retained_attempt),
        progress=_capture_progress_snapshot(retained_progress),
    )


def _attempt_projection(snapshot: _AttemptSnapshot) -> tuple[object, ...]:
    return (
        snapshot.artifact_sha256,
        snapshot.artifact_path,
        snapshot.encoded,
        snapshot.file_identity,
    )


def _progress_projection(snapshot: _ProgressSnapshot) -> tuple[object, ...]:
    return (
        snapshot.artifact_sha256,
        snapshot.artifact_path,
        snapshot.encoded,
        snapshot.file_identity,
        snapshot.attempt_slot_file_identity,
    )


def _require_snapshot_current(snapshot: _RequestEvidenceSnapshot) -> None:
    _require_consumed_receipt_snapshot_current(snapshot.receipt)
    current = _capture_request_evidence_snapshot(
        decision_artifact_receipt=snapshot.receipt,
        retained_attempt=snapshot.attempt.identity,
        retained_progress=snapshot.progress.identity,
    )
    if (
        current.receipt is not snapshot.receipt
        or current.receipt.values != snapshot.receipt.values
        or current.receipt.encoded != snapshot.receipt.encoded
        or current.receipt.receipt_sha256 != snapshot.receipt.receipt_sha256
        or current.attempt.identity is not snapshot.attempt.identity
        or current.attempt.record_identity is not snapshot.attempt.record_identity
        or _attempt_projection(current.attempt) != _attempt_projection(snapshot.attempt)
        or current.progress.identity is not snapshot.progress.identity
        or current.progress.record_identity is not snapshot.progress.record_identity
        or _progress_projection(current.progress) != _progress_projection(snapshot.progress)
    ):
        raise ValueError


def _require_inspected_chain(
    snapshot: _RequestEvidenceSnapshot,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    state = inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    state.__post_init__()
    if (
        state.status
        is not TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
        or state.attempt is None
        or state.progress is None
        or state.outcome is not None
    ):
        raise ValueError
    observed_attempt = _capture_attempt_snapshot(state.attempt)
    observed_progress = _capture_progress_snapshot(state.progress)
    if _attempt_projection(observed_attempt) != _attempt_projection(
        snapshot.attempt
    ) or _progress_projection(observed_progress) != _progress_projection(snapshot.progress):
        raise ValueError


def _local_chain_records(snapshot: _RequestEvidenceSnapshot) -> tuple[Any, Any]:
    attempt_record = decode_post_enrollment_graceful_stop_attempt_bytes(snapshot.attempt.encoded)
    progress_record = decode_post_enrollment_graceful_stop_progress_bytes(snapshot.progress.encoded)
    if (
        attempt_record.record_sha256 != snapshot.attempt.artifact_sha256
        or progress_record.record_sha256 != snapshot.progress.artifact_sha256
        or progress_record.graceful_stop_operation_id != attempt_record.graceful_stop_operation_id
        or progress_record.graceful_stop_target_sha256 != attempt_record.graceful_stop_target_sha256
        or progress_record.graceful_stop_decision_v1_sha256
        != attempt_record.graceful_stop_decision_v1_sha256
        or progress_record.operator_attestation_envelope_sha256
        != attempt_record.operator_attestation_envelope_sha256
        or progress_record.attempt_slot_sha256 != snapshot.attempt.artifact_sha256
        or progress_record.predecessor_record_sha256 != snapshot.attempt.artifact_sha256
        or snapshot.progress.attempt_slot_file_identity != snapshot.attempt.file_identity
    ):
        raise ValueError
    return attempt_record, progress_record


def _request_from_snapshot(
    snapshot: _RequestEvidenceSnapshot,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    attempt_record, _ = _local_chain_records(snapshot)
    receipt_values = _decode_receipt_identity_values(snapshot.receipt.encoded)
    if receipt_values != snapshot.receipt.values:
        raise ValueError
    receipt = dict(zip(_DECISION_RECEIPT_IDENTITY_FIELDS, receipt_values, strict=True))
    locator = attempt_record.durable_shutdown_locator
    topology = locator.persistent_topology
    approved_launch = topology.get("approved_launch")
    supervisor = topology.get("supervisor_container")
    if type(approved_launch) is not dict or type(supervisor) is not dict:
        raise ValueError
    launch = cast(dict[str, object], approved_launch)
    supervisor_container_id = cast(dict[str, object], supervisor).get("container_id")
    if (
        receipt["graceful_stop_operation_id"] != attempt_record.graceful_stop_operation_id
        or receipt["graceful_stop_target_sha256"] != attempt_record.graceful_stop_target_sha256
        or receipt["graceful_stop_decision_v1_sha256"]
        != attempt_record.graceful_stop_decision_v1_sha256
        or receipt["controller_outcome_sha256"] != attempt_record.controller_outcome_sha256
        or receipt["durable_shutdown_locator_sha256"]
        != attempt_record.durable_shutdown_locator_sha256
        or receipt["start_operation_id"] != attempt_record.start_operation_id
        or receipt["start_approval_sha256"] != attempt_record.start_approval_sha256
        or receipt["start_execution_attempt_slot_sha256"]
        != attempt_record.start_execution_attempt_slot_sha256
        or receipt["start_operator_attestation_envelope_sha256"]
        != attempt_record.start_operator_attestation_envelope_sha256
        or receipt["start_git_revision"] != launch.get("git_revision")
        or receipt["start_approved_image_provenance_sha256"] != launch.get("image_admission_sha256")
        or receipt["start_source_image_id"] != launch.get("source_image_id")
        or receipt["start_supervisor_image_id"] != launch.get("supervisor_image_id")
        or not _is_sha256(supervisor_container_id)
    ):
        raise ValueError
    return TrustedTimeHeadAnchorOperationBoundCleanStopRequest(
        graceful_stop_operation_id=attempt_record.graceful_stop_operation_id,
        graceful_stop_target_sha256=attempt_record.graceful_stop_target_sha256,
        graceful_stop_decision_v1_sha256=attempt_record.graceful_stop_decision_v1_sha256,
        graceful_stop_decision_artifact_receipt_sha256=snapshot.receipt.receipt_sha256,
        operator_attestation_envelope_sha256=(attempt_record.operator_attestation_envelope_sha256),
        attempt_slot_sha256=snapshot.attempt.artifact_sha256,
        bridge_required_progress_sha256=snapshot.progress.artifact_sha256,
        controller_outcome_sha256=attempt_record.controller_outcome_sha256,
        durable_shutdown_locator_sha256=attempt_record.durable_shutdown_locator_sha256,
        active_controller_session_sha256=locator.active_controller_session_sha256,
        persistent_topology_sha256=locator.persistent_topology_sha256,
        persistent_topology_transcript_sha256=(locator.persistent_topology_transcript_sha256),
        supervisor_container_id=cast(str, supervisor_container_id),
    )


def _request_from_exact_evidence(
    *,
    decision_artifact_receipt: _DecisionReceiptSnapshot,
    retained_attempt: object,
    retained_progress: object,
    artifact_directory: object,
    ignored_root: object,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    exact_directory, exact_root = _exact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    snapshot = _capture_request_evidence_snapshot(
        decision_artifact_receipt=decision_artifact_receipt,
        retained_attempt=retained_attempt,
        retained_progress=retained_progress,
    )
    _require_inspected_chain(
        snapshot,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    _require_snapshot_current(snapshot)
    request = _request_from_snapshot(snapshot)
    request_wire = _capture_request_wire_snapshot(request)
    _require_snapshot_current(snapshot)
    _require_inspected_chain(
        snapshot,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    _require_snapshot_current(snapshot)
    rebuilt = _request_from_snapshot(snapshot)
    if _capture_request_wire_snapshot(rebuilt) != request_wire:
        raise ValueError
    return request


def build_post_enrollment_graceful_stop_supervisor_clean_stop_request(
    *,
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ),
    start_operator_attested_approval_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    artifact_directory: Path,
    ignored_root: Path,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    """Authenticate one loaded receipt and bind its consumed snapshot to one request."""

    bridge_identity = _new_bridge_identity()
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest | None = None
    try:
        consumed_receipt = _authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge(  # noqa: E501
            loaded_decision_artifact_receipt,
            start_operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
            expected_graceful_stop_decision_v1_sha256=(expected_graceful_stop_decision_v1_sha256),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            consumer_identity=bridge_identity,
        )
        receipt_snapshot = _capture_consumed_receipt_snapshot(
            consumed_receipt,
            loaded_identity=loaded_decision_artifact_receipt,
            bridge_identity=bridge_identity,
        )
        request = _request_from_exact_evidence(
            decision_artifact_receipt=receipt_snapshot,
            retained_attempt=retained_attempt,
            retained_progress=retained_progress,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        request_evidence_snapshot = _capture_request_evidence_snapshot(
            decision_artifact_receipt=receipt_snapshot,
            retained_attempt=retained_attempt,
            retained_progress=retained_progress,
        )
        _require_snapshot_current(request_evidence_snapshot)
        request_wire_snapshot = _capture_request_wire_snapshot(request)
        registration = _register_authenticated_request(
            request=request,
            loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
            bridge_identity=bridge_identity,
            request_evidence_snapshot=request_evidence_snapshot,
            request_wire_snapshot=request_wire_snapshot,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        _validate_authenticated_request_registration(
            request,
            loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
            registration=registration,
        )
        return request
    except BaseException as error:
        cleanup_error: BaseException | None = None
        cleanup_transition_error: BaseException | None = None
        cleanup_retry_error: BaseException | None = None
        if request is not None:
            try:
                try:
                    cleanup_error = _revoke_authenticated_request_if_registered(
                        request,
                        loaded_decision_artifact_receipt=(loaded_decision_artifact_receipt),
                    )
                except BaseException as observed_cleanup_error:
                    cleanup_transition_error = observed_cleanup_error
            finally:
                try:
                    cleanup_retry_error = _revoke_authenticated_request_if_registered(
                        request,
                        loaded_decision_artifact_receipt=(loaded_decision_artifact_receipt),
                    )
                except BaseException as observed_retry_error:
                    cleanup_retry_error = observed_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            cleanup_transition_error,
            cleanup_error,
            cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected,
        ):
            raise
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor request is unavailable"
        ) from None


@dataclass(slots=True)
class _AuthenticatedRequestRegistration:
    request_reference: weakref.ReferenceType[TrustedTimeHeadAnchorOperationBoundCleanStopRequest]
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    )
    bridge_identity: _BridgeIdentity
    owner_pid: int
    owner_thread: threading.Thread
    request_sha256: str
    request_evidence_snapshot: _RequestEvidenceSnapshot
    request_wire_snapshot: _RequestWireSnapshot
    artifact_directory: Path
    ignored_root: Path
    source_identities: tuple[object, ...]


_AUTHENTICATED_REQUEST_REGISTRY_LOCK = threading.Lock()
_AUTHENTICATED_REQUEST_REGISTRY: dict[int, _AuthenticatedRequestRegistration] = {}
_AUTHENTICATED_REQUEST_ID_BY_LOADED_ID: dict[int, int] = {}
_AUTHENTICATED_REQUEST_ID_BY_SHA256: dict[str, int] = {}
_SEEN_AUTHENTICATED_REQUEST_SHA256S: set[str] = set()


def _preferred_registry_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_registry_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_registry_exception(preferred, error)
    return preferred


def _remove_authenticated_request_registration_locked(
    request_id: int,
    registration: _AuthenticatedRequestRegistration,
) -> None:
    if _AUTHENTICATED_REQUEST_REGISTRY.get(request_id) is registration:
        _AUTHENTICATED_REQUEST_REGISTRY.pop(request_id, None)
    loaded_id = id(registration.loaded_decision_artifact_receipt)
    if _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.get(loaded_id) == request_id:
        _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.pop(loaded_id, None)
    if _AUTHENTICATED_REQUEST_ID_BY_SHA256.get(registration.request_sha256) == request_id:
        _AUTHENTICATED_REQUEST_ID_BY_SHA256.pop(registration.request_sha256, None)


def _burn_authenticated_request_registration_keys(
    *,
    request_id: int,
    loaded_id: int,
    request_sha256: str | None,
    expected_reference: weakref.ReferenceType[TrustedTimeHeadAnchorOperationBoundCleanStopRequest]
    | None = None,
) -> BaseException | None:
    """Best-effort idempotent burn of every index for one request association."""

    if os.getpid() != _ORIGIN_PID:
        return None
    first_error: BaseException | None = None
    for _ in range(16):
        clean = False
        try:
            with _AUTHENTICATED_REQUEST_REGISTRY_LOCK:
                candidate_ids = {request_id}
                loaded_request_id = _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.get(loaded_id)
                if loaded_request_id is not None:
                    candidate_ids.add(loaded_request_id)
                if request_sha256 is not None:
                    digest_request_id = _AUTHENTICATED_REQUEST_ID_BY_SHA256.get(request_sha256)
                    if digest_request_id is not None:
                        candidate_ids.add(digest_request_id)
                for candidate_id in candidate_ids:
                    registration = _AUTHENTICATED_REQUEST_REGISTRY.get(candidate_id)
                    if registration is None:
                        continue
                    if (
                        expected_reference is not None
                        and registration.request_reference is not expected_reference
                    ):
                        continue
                    try:
                        _remove_authenticated_request_registration_locked(
                            candidate_id,
                            registration,
                        )
                    except BaseException as error:
                        first_error = _preferred_registry_exception(first_error, error)
                for loaded_key, candidate_id in tuple(
                    _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.items()
                ):
                    if (
                        candidate_id in candidate_ids
                        and _AUTHENTICATED_REQUEST_REGISTRY.get(candidate_id) is None
                    ):
                        _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.pop(loaded_key, None)
                for digest_key, candidate_id in tuple(_AUTHENTICATED_REQUEST_ID_BY_SHA256.items()):
                    if (
                        candidate_id in candidate_ids
                        and _AUTHENTICATED_REQUEST_REGISTRY.get(candidate_id) is None
                    ):
                        _AUTHENTICATED_REQUEST_ID_BY_SHA256.pop(digest_key, None)
                if all(
                    _AUTHENTICATED_REQUEST_REGISTRY.get(candidate_id) is None
                    for candidate_id in candidate_ids
                ) and all(
                    candidate_id not in candidate_ids
                    for index in (
                        _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID,
                        _AUTHENTICATED_REQUEST_ID_BY_SHA256,
                    )
                    for candidate_id in index.values()
                ):
                    clean = True
        except BaseException as error:
            first_error = _preferred_registry_exception(first_error, error)
        if clean:
            return first_error
    return _preferred_registry_exception(
        first_error,
        RuntimeError("authenticated request registry entry could not be revoked"),
    )


def _burn_authenticated_request_targets(
    request: object,
    *,
    loaded_decision_artifact_receipt: object,
) -> BaseException | None:
    request_sha256: str | None = None
    capture_error: BaseException | None = None
    if type(request) is TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
        try:
            request_sha256 = _capture_request_wire_snapshot(request).request_sha256
        except BaseException as error:
            capture_error = error
    cleanup_error = _burn_authenticated_request_registration_keys(
        request_id=id(request),
        loaded_id=id(loaded_decision_artifact_receipt),
        request_sha256=request_sha256,
    )
    return _preferred_registry_exception(capture_error, cleanup_error)


def _revoke_authenticated_request_if_registered(
    request: object,
    *,
    loaded_decision_artifact_receipt: object,
) -> BaseException | None:
    return _burn_authenticated_request_targets(
        request,
        loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
    )


def _validate_authenticated_request_registration_values(
    request: object,
    *,
    loaded_decision_artifact_receipt: object,
    registration: _AuthenticatedRequestRegistration,
) -> None:
    if (
        os.getpid() != _ORIGIN_PID
        or type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
        or type(loaded_decision_artifact_receipt)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(registration) is not _AuthenticatedRequestRegistration
        or registration.request_reference() is not request
        or registration.loaded_decision_artifact_receipt is not loaded_decision_artifact_receipt
        or type(registration.bridge_identity) is not _BridgeIdentity
        or registration.owner_pid != os.getpid()
        or registration.owner_thread is not threading.current_thread()
        or registration.request_evidence_snapshot.receipt.loaded_identity
        is not loaded_decision_artifact_receipt
        or registration.request_evidence_snapshot.receipt.bridge_identity
        is not registration.bridge_identity
    ):
        raise ValueError
    sources = (
        loaded_decision_artifact_receipt,
        registration.request_evidence_snapshot.receipt.consumed_identity,
        registration.request_evidence_snapshot.attempt.identity,
        registration.request_evidence_snapshot.progress.identity,
        registration.bridge_identity,
    )
    if len(registration.source_identities) != len(sources) or any(
        observed is not captured
        for observed, captured in zip(sources, registration.source_identities, strict=True)
    ):
        raise ValueError
    exact_directory, exact_root = _exact_roots(
        registration.artifact_directory,
        ignored_root=registration.ignored_root,
    )
    _require_snapshot_current(registration.request_evidence_snapshot)
    _require_inspected_chain(
        registration.request_evidence_snapshot,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    current_request = _capture_request_wire_snapshot(request)
    expected_request = _capture_request_wire_snapshot(
        _request_from_snapshot(registration.request_evidence_snapshot)
    )
    if (
        current_request != registration.request_wire_snapshot
        or expected_request != registration.request_wire_snapshot
        or registration.request_sha256 != registration.request_wire_snapshot.request_sha256
    ):
        raise ValueError


def _validate_authenticated_request_registration(
    request: object,
    *,
    loaded_decision_artifact_receipt: object,
    registration: _AuthenticatedRequestRegistration,
) -> None:
    if os.getpid() != _ORIGIN_PID:
        raise ValueError
    with _AUTHENTICATED_REQUEST_REGISTRY_LOCK:
        if _AUTHENTICATED_REQUEST_REGISTRY.get(id(request)) is not registration:
            raise ValueError
    _validate_authenticated_request_registration_values(
        request,
        loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
        registration=registration,
    )


def _register_authenticated_request(
    *,
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ),
    bridge_identity: _BridgeIdentity,
    request_evidence_snapshot: _RequestEvidenceSnapshot,
    request_wire_snapshot: _RequestWireSnapshot,
    artifact_directory: Path,
    ignored_root: Path,
) -> _AuthenticatedRequestRegistration:
    if os.getpid() != _ORIGIN_PID:
        raise ValueError
    exact_directory, exact_root = _exact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    if (
        type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
        or type(loaded_decision_artifact_receipt)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(bridge_identity) is not _BridgeIdentity
        or type(request_evidence_snapshot) is not _RequestEvidenceSnapshot
        or type(request_wire_snapshot) is not _RequestWireSnapshot
        or request_evidence_snapshot.receipt.loaded_identity is not loaded_decision_artifact_receipt
        or request_evidence_snapshot.receipt.bridge_identity is not bridge_identity
        or _capture_request_wire_snapshot(request) != request_wire_snapshot
        or _capture_request_wire_snapshot(_request_from_snapshot(request_evidence_snapshot))
        != request_wire_snapshot
    ):
        raise ValueError
    request_id = id(request)
    loaded_id = id(loaded_decision_artifact_receipt)
    request_sha256 = request_wire_snapshot.request_sha256
    owner_thread = threading.current_thread()

    def request_lost(
        reference: weakref.ReferenceType[TrustedTimeHeadAnchorOperationBoundCleanStopRequest],
    ) -> None:
        _burn_authenticated_request_registration_keys(
            request_id=request_id,
            loaded_id=loaded_id,
            request_sha256=request_sha256,
            expected_reference=reference,
        )

    reference = weakref.ref(request, request_lost)
    registration = _AuthenticatedRequestRegistration(
        request_reference=reference,
        loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
        bridge_identity=bridge_identity,
        owner_pid=os.getpid(),
        owner_thread=owner_thread,
        request_sha256=request_sha256,
        request_evidence_snapshot=request_evidence_snapshot,
        request_wire_snapshot=request_wire_snapshot,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
        source_identities=(
            loaded_decision_artifact_receipt,
            request_evidence_snapshot.receipt.consumed_identity,
            request_evidence_snapshot.attempt.identity,
            request_evidence_snapshot.progress.identity,
            bridge_identity,
        ),
    )
    with _AUTHENTICATED_REQUEST_REGISTRY_LOCK:
        if (
            request_id in _AUTHENTICATED_REQUEST_REGISTRY
            or loaded_id in _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID
            or request_sha256 in _SEEN_AUTHENTICATED_REQUEST_SHA256S
        ):
            raise ValueError
        _SEEN_AUTHENTICATED_REQUEST_SHA256S.add(request_sha256)
        _AUTHENTICATED_REQUEST_REGISTRY[request_id] = registration
        _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID[loaded_id] = request_id
        _AUTHENTICATED_REQUEST_ID_BY_SHA256[request_sha256] = request_id
    return registration


def _consume_authenticated_request_registration(
    request: object,
    *,
    loaded_decision_artifact_receipt: object,
) -> _AuthenticatedRequestRegistration:
    if (
        os.getpid() != _ORIGIN_PID
        or type(loaded_decision_artifact_receipt)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ):
        raise ValueError
    candidate_ids = {id(request)}
    with _AUTHENTICATED_REQUEST_REGISTRY_LOCK:
        loaded_request_id = _AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.get(
            id(loaded_decision_artifact_receipt)
        )
        if loaded_request_id is not None:
            candidate_ids.add(loaded_request_id)
        observed_registrations: list[_AuthenticatedRequestRegistration] = []
        for candidate_id in candidate_ids:
            observed = _AUTHENTICATED_REQUEST_REGISTRY.get(candidate_id)
            if observed is not None and all(
                observed is not existing for existing in observed_registrations
            ):
                observed_registrations.append(observed)
        registrations = tuple(observed_registrations)
        for registration in registrations:
            registered_request_id = _AUTHENTICATED_REQUEST_ID_BY_SHA256.get(
                registration.request_sha256
            )
            if registered_request_id is not None:
                _remove_authenticated_request_registration_locked(
                    registered_request_id,
                    registration,
                )
    if not registrations:
        request_snapshot: _RequestWireSnapshot | None = None
        if type(request) is TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
            try:
                request_snapshot = _capture_request_wire_snapshot(request)
            except Exception:
                request_snapshot = None
        if request_snapshot is not None:
            with _AUTHENTICATED_REQUEST_REGISTRY_LOCK:
                digest_request_id = _AUTHENTICATED_REQUEST_ID_BY_SHA256.get(
                    request_snapshot.request_sha256
                )
                if digest_request_id is not None:
                    digest_registration = _AUTHENTICATED_REQUEST_REGISTRY.get(digest_request_id)
                    if digest_registration is not None:
                        _remove_authenticated_request_registration_locked(
                            digest_request_id,
                            digest_registration,
                        )
                        registrations = (digest_registration,)
    if len(registrations) != 1:
        raise ValueError
    # Return the already-popped association without inspecting its nested values.
    # The binder needs its exact identity to burn ADR-0109 before any remaining
    # request, loaded-receipt, source-chain, or terminal validation can fail.
    return registrations[0]


@dataclass(slots=True)
class _CompositeRegistration:
    reference: weakref.ReferenceType[
        TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation
    ]
    owner_pid: int
    owner_thread: threading.Thread
    values: tuple[object, ...]
    semantic_sha256: str
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    )
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest
    result: TrustedTimeHeadAnchorOperationBoundCleanStopResult
    terminal_postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    terminal_reauthentication_issuer: (
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    )
    bridge_identity: _BridgeIdentity
    authenticated_request_registration: _AuthenticatedRequestRegistration
    source_identities: tuple[object, ...]
    request_evidence_snapshot: _RequestEvidenceSnapshot
    request_wire_snapshot: _RequestWireSnapshot
    result_wire_snapshot: _ResultWireSnapshot
    postcondition_registry_snapshot: _ConsumedPostconditionRegistrySnapshot
    issuer_binding_sha256: str
    read_only_configuration_sha256: str


_COMPOSITE_REGISTRY_LOCK = threading.Lock()
_COMPOSITE_REGISTRY: dict[int, _CompositeRegistration] = {}


def _composite_values(
    value: TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation,
) -> tuple[object, ...]:
    return tuple(object.__getattribute__(value, name) for name in _COMPOSITE_FIELDS)


def _postcondition_projection(
    snapshot: _ConsumedPostconditionRegistrySnapshot,
) -> dict[str, object]:
    values = (*snapshot.values, snapshot.semantic_sha256)
    if len(values) != len(_POSTCONDITION_SNAPSHOT_FIELDS):
        raise ValueError
    return dict(zip(_POSTCONDITION_SNAPSHOT_FIELDS, values, strict=True))


def _composite_field_values(
    *,
    request: _RequestWireSnapshot,
    result: _ResultWireSnapshot,
    terminal_postcondition: _ConsumedPostconditionRegistrySnapshot,
) -> dict[str, object]:
    request_projection = dict(zip(_REQUEST_BINDING_FIELDS, request.values, strict=True))
    result_projection = dict(zip(_RESULT_TERMINAL_FIELDS, result.values, strict=True))
    postcondition_projection = _postcondition_projection(terminal_postcondition)
    fields = dict(request_projection)
    fields.update(
        {
            "operation_bound_request_sha256": request.request_sha256,
            "operation_bound_result_sha256": result.result_sha256,
        }
    )
    fields.update(result_projection)
    fields.update(
        {name: postcondition_projection[name] for name in _REAUTHENTICATION_BINDING_FIELDS}
    )
    fields["terminal_reauthentication_semantic_sha256"] = terminal_postcondition.semantic_sha256
    if set(fields) != set(_COMPOSITE_FIELDS):
        raise ValueError
    return fields


def _validate_composite_values(values: tuple[object, ...]) -> None:
    projection = dict(zip(_COMPOSITE_FIELDS, values, strict=True))
    if (
        len(values) != len(_COMPOSITE_FIELDS)
        or not _is_uuid4(projection["graceful_stop_operation_id"])
        or any(
            not _is_sha256(value) for name, value in projection.items() if name.endswith("_sha256")
        )
        or not _is_sha256(projection["supervisor_container_id"])
        or projection["checkpoint_reason"] is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        or type(projection["receipt_observed_at_utc"]) is not datetime
        or projection["receipt_observed_at_utc"].tzinfo is None
        or projection["receipt_observed_at_utc"].utcoffset()
        != UTC.utcoffset(projection["receipt_observed_at_utc"])
        or any(
            type(projection[name]) is not int
            for name in (
                "request_sequence",
                "request_scheduled_monotonic_ns",
                "anchor_sequence",
                "confirmed_anchor_count",
                "local_transition_count",
                "confirmed_anchor_local_transition_ordinal",
                "uploaded_anchor_count",
                "idempotent_duplicate_count",
                "remote_object_count",
                "observation_started_monotonic_ns",
                "observation_completed_monotonic_ns",
                "deadline_monotonic_ns",
            )
        )
        or type(projection["full_audit_completed"]) is not bool
        or type(projection["prior_pending_intent_recovered"]) is not bool
    ):
        raise ValueError


def _composite_payload(
    value: TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update({name: object.__getattribute__(value, name) for name in _COMPOSITE_FIELDS})
    payload["checkpoint_reason"] = value.checkpoint_reason.value
    payload["receipt_observed_at_utc"] = _utc_text(value.receipt_observed_at_utc)
    payload.update(
        {
            "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_CONTRACT_VERSION,
            "decision_artifact_receipt_authenticated": True,
            "exact_terminal_projection_cross_bound_unqualified": True,
            "historical_start_chain_authenticated": True,
            "provider_terminal_observed_under_stable_sql_authenticated": True,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS,
        }
    )
    return payload


def _validate_registered_composite(value: object) -> None:
    try:
        if (
            os.getpid() != _ORIGIN_PID
            or type(value)
            is not TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation
        ):
            raise ValueError
        exact = value
        values = _composite_values(exact)
        _validate_composite_values(values)
        semantic_sha256 = object.__getattribute__(exact, "_semantic_sha256")
        with _COMPOSITE_REGISTRY_LOCK:
            registration = _COMPOSITE_REGISTRY.get(id(exact))
        if (
            registration is None
            or registration.reference() is not exact
            or registration.owner_pid != os.getpid()
            or registration.owner_thread is not threading.current_thread()
            or registration.values != values
            or registration.semantic_sha256 != semantic_sha256
            or not _is_sha256(semantic_sha256)
            or semantic_sha256
            != hashlib.sha256(
                canonical_first_enrollment_json_bytes(_composite_payload(exact))
            ).hexdigest()
            or type(registration.bridge_identity) is not _BridgeIdentity
        ):
            raise ValueError
        sources = (
            registration.loaded_decision_artifact_receipt,
            registration.request_evidence_snapshot.receipt.consumed_identity,
            registration.authenticated_request_registration,
            registration.retained_attempt,
            registration.retained_progress,
            registration.request,
            registration.result,
            registration.terminal_postcondition,
            registration.terminal_reauthentication_issuer,
            registration.bridge_identity,
        )
        if (
            len(registration.source_identities) != len(sources)
            or any(
                observed is not captured
                for observed, captured in zip(
                    sources,
                    registration.source_identities,
                    strict=True,
                )
            )
            or type(registration.loaded_decision_artifact_receipt)
            is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
            or type(registration.authenticated_request_registration)
            is not _AuthenticatedRequestRegistration
            or type(registration.retained_attempt)
            is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
            or type(registration.retained_progress)
            is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
            or type(registration.request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
            or type(registration.result) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult
            or type(registration.terminal_postcondition)
            is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
            or type(registration.terminal_reauthentication_issuer)
            is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            or type(registration.bridge_identity) is not _BridgeIdentity
            or registration.request_evidence_snapshot.receipt.loaded_identity
            is not registration.loaded_decision_artifact_receipt
            or registration.request_evidence_snapshot.receipt.bridge_identity
            is not registration.bridge_identity
            or registration.request_evidence_snapshot.attempt.identity
            is not registration.retained_attempt
            or registration.request_evidence_snapshot.progress.identity
            is not registration.retained_progress
        ):
            raise ValueError
        _validate_authenticated_request_registration_values(
            registration.request,
            loaded_decision_artifact_receipt=(registration.loaded_decision_artifact_receipt),
            registration=registration.authenticated_request_registration,
        )
        _require_snapshot_current(registration.request_evidence_snapshot)
        expected_request = _capture_request_wire_snapshot(
            _request_from_snapshot(registration.request_evidence_snapshot)
        )
        stored_request = _decode_request_wire_snapshot(registration.request_wire_snapshot.encoded)
        stored_result = _decode_result_wire_snapshot(registration.result_wire_snapshot.encoded)
        current_request = _capture_request_wire_snapshot(registration.request)
        current_result = _capture_result_wire_snapshot(registration.result)
        current_postcondition = _require_consumed_postcondition_snapshot(
            _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
                registration.terminal_postcondition,
                issuer=registration.terminal_reauthentication_issuer,
                bridge_identity=registration.bridge_identity,
            ),
            issuer=registration.terminal_reauthentication_issuer,
            bridge_identity=registration.bridge_identity,
        )
        postcondition_projection = _postcondition_projection(current_postcondition)
        if (
            stored_request != registration.request_wire_snapshot
            or stored_result != registration.result_wire_snapshot
            or current_request != stored_request
            or current_result != stored_result
            or expected_request != stored_request
            or stored_result.request != stored_request
            or not _same_consumed_postcondition_snapshot(
                current_postcondition,
                registration.postcondition_registry_snapshot,
            )
            or postcondition_projection["issuer_binding_sha256"]
            != registration.issuer_binding_sha256
            or postcondition_projection["read_only_configuration_sha256"]
            != registration.read_only_configuration_sha256
            or not _terminal_projection_matches(stored_result, current_postcondition)
        ):
            raise ValueError
        derived_fields = _composite_field_values(
            request=stored_request,
            result=stored_result,
            terminal_postcondition=current_postcondition,
        )
        if tuple(derived_fields[name] for name in _COMPOSITE_FIELDS) != values:
            raise ValueError
    except TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor terminal observation is invalid"
        ) from None


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False, eq=False)
class TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation(
    _ClosedHostBridgeEvidence
):
    """Sealed same-process evidence of one exact unqualified terminal cross-binding."""

    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_decision_artifact_receipt_sha256: str
    operator_attestation_envelope_sha256: str
    attempt_slot_sha256: str
    bridge_required_progress_sha256: str
    controller_outcome_sha256: str
    durable_shutdown_locator_sha256: str
    active_controller_session_sha256: str
    persistent_topology_sha256: str
    persistent_topology_transcript_sha256: str
    supervisor_container_id: str
    operation_bound_request_sha256: str
    operation_bound_result_sha256: str
    request_sequence: int
    request_scheduled_monotonic_ns: int
    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    predecessor_anchor_sha256: str
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    receipt_observed_at_utc: datetime
    full_audit_completed: bool
    prior_pending_intent_recovered: bool
    uploaded_anchor_count: int
    idempotent_duplicate_count: int
    current_anchor_intent_semantic_sha256: str
    current_candidate_remote_readback_sha256: str
    current_receipt_semantic_sha256: str
    clean_stop_terminal_result_semantic_sha256: str
    remote_object_count: int
    remote_observation_sha256: str
    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    source_authority_sha256: str
    signing_public_key_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    bucket_identity_sha256: str
    observation_started_monotonic_ns: int
    observation_completed_monotonic_ns: int
    deadline_monotonic_ns: int
    issuer_binding_sha256: str
    read_only_configuration_sha256: str
    terminal_reauthentication_semantic_sha256: str
    _semantic_sha256: str = field(repr=False, compare=False)

    def __new__(
        cls,
    ) -> TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor terminal observation must be issued"
        )

    def __post_init__(self) -> None:
        _validate_registered_composite(self)

    @_EVIDENCE_PROPERTY
    def contract_version(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_CONTRACT_VERSION

    @_EVIDENCE_PROPERTY
    def service(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE

    @_EVIDENCE_PROPERTY
    def status(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS

    @_EVIDENCE_PROPERTY
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return self._semantic_sha256

    @_EVIDENCE_PROPERTY
    def provider_terminal_observed_under_stable_sql_authenticated(self) -> bool:
        self.__post_init__()
        return True

    @_EVIDENCE_PROPERTY
    def exact_terminal_projection_cross_bound_unqualified(self) -> bool:
        self.__post_init__()
        return True

    @_EVIDENCE_PROPERTY
    def decision_artifact_receipt_authenticated(self) -> bool:
        self.__post_init__()
        return True

    @_EVIDENCE_PROPERTY
    def historical_start_chain_authenticated(self) -> bool:
        self.__post_init__()
        return True

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        return _composite_payload(self)

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __replace__(self, **_: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        _cannot_copy()


from packages.application.trusted_time_head_anchor import (  # noqa: E402
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge import (  # noqa: E402
    TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    TrustedTimeHeadAnchorOperationBoundCleanStopResult,
    canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes,
    canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes,
    decode_trusted_time_head_anchor_operation_bound_clean_stop_request,
    decode_trusted_time_head_anchor_operation_bound_clean_stop_result,
)
from packages.domain.trusted_time_enrollment_evidence import (  # noqa: E402
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (  # noqa: E402
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once,
    _ConsumedPostconditionRegistrySnapshot,
    _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (  # noqa: E402
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
)
from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts import (  # noqa: E402
    ARTIFACT_RECEIPT_CONTRACT_VERSION,
    ARTIFACT_WORKFLOW_SERVICE,
    DECISION_CANDIDATE_PREPARED_STATUS,
    POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS,
    LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    _authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge,
    _ConsumedLoadedDecisionArtifactReceiptSnapshot,
    _require_consumed_loaded_decision_artifact_receipt_snapshot,
)
from scripts.trusted_time_post_enrollment_graceful_stop_lifecycle import (  # noqa: E402
    RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus,
    decode_post_enrollment_graceful_stop_attempt_bytes,
    decode_post_enrollment_graceful_stop_progress_bytes,
    inspect_post_enrollment_graceful_stop_recovery_state,
)

if _BUILTINS.property is not _EVIDENCE_PROPERTY:
    raise RuntimeError("builtins.property changed during bridge dependency imports")


def _terminal_projection_matches(
    result: _ResultWireSnapshot,
    postcondition: _ConsumedPostconditionRegistrySnapshot,
) -> bool:
    result_projection = dict(zip(_RESULT_TERMINAL_FIELDS, result.values, strict=True))
    postcondition_projection = _postcondition_projection(postcondition)
    return (
        result_projection["anchor_sequence"] == postcondition_projection["anchor_sequence"]
        and result_projection["checkpoint_reason"] is postcondition_projection["checkpoint_reason"]
        and result_projection["confirmed_anchor_count"]
        == postcondition_projection["confirmed_anchor_count"]
        and result_projection["local_transition_count"]
        == postcondition_projection["local_transition_count"]
        and result_projection["confirmed_anchor_local_transition_ordinal"]
        == postcondition_projection["confirmed_anchor_local_transition_ordinal"]
        and result_projection["predecessor_anchor_sha256"]
        == postcondition_projection["predecessor_anchor_sha256"]
        and result_projection["current_host_head_sha256"]
        == postcondition_projection["current_host_head_sha256"]
        and result_projection["current_anchor_sha256"]
        == postcondition_projection["current_anchor_sha256"]
        and result_projection["current_anchor_semantic_sha256"]
        == postcondition_projection["current_anchor_semantic_sha256"]
        and result_projection["current_anchor_intent_semantic_sha256"]
        == postcondition_projection["anchor_intent_semantic_sha256"]
        and result_projection["current_candidate_remote_readback_sha256"]
        == postcondition_projection["candidate_remote_readback_sha256"]
        and result_projection["current_receipt_semantic_sha256"]
        == postcondition_projection["receipt_semantic_sha256"]
        and result_projection["receipt_observed_at_utc"]
        == postcondition_projection["receipt_observed_at_utc"]
    )


def _issue_composite(
    *,
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ),
    authenticated_request_registration: _AuthenticatedRequestRegistration,
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    result: TrustedTimeHeadAnchorOperationBoundCleanStopResult,
    terminal_postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    terminal_reauthentication_issuer: (
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    ),
    bridge_identity: _BridgeIdentity,
    request_wire_snapshot: _RequestWireSnapshot,
    result_wire_snapshot: _ResultWireSnapshot,
    postcondition_registry_snapshot: _ConsumedPostconditionRegistrySnapshot,
) -> TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation:
    if os.getpid() != _ORIGIN_PID:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor terminal observation is unavailable"
        )
    if (
        type(loaded_decision_artifact_receipt)
        is not LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        or type(authenticated_request_registration) is not _AuthenticatedRequestRegistration
        or type(retained_attempt) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
        or type(retained_progress) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
        or type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
        or type(result) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult
        or type(terminal_postcondition)
        is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
        or type(terminal_reauthentication_issuer)
        is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
        or type(bridge_identity) is not _BridgeIdentity
        or type(request_wire_snapshot) is not _RequestWireSnapshot
        or type(result_wire_snapshot) is not _ResultWireSnapshot
        or type(postcondition_registry_snapshot) is not _ConsumedPostconditionRegistrySnapshot
    ):
        raise ValueError
    if (
        authenticated_request_registration.bridge_identity is not bridge_identity
        or authenticated_request_registration.loaded_decision_artifact_receipt
        is not loaded_decision_artifact_receipt
        or authenticated_request_registration.request_reference() is not request
        or authenticated_request_registration.request_evidence_snapshot.attempt.identity
        is not retained_attempt
        or authenticated_request_registration.request_evidence_snapshot.progress.identity
        is not retained_progress
    ):
        raise ValueError
    _validate_authenticated_request_registration_values(
        request,
        loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
        registration=authenticated_request_registration,
    )
    request_evidence_snapshot = authenticated_request_registration.request_evidence_snapshot
    _require_snapshot_current(request_evidence_snapshot)
    expected_request = _capture_request_wire_snapshot(
        _request_from_snapshot(request_evidence_snapshot)
    )
    stored_request = _decode_request_wire_snapshot(request_wire_snapshot.encoded)
    stored_result = _decode_result_wire_snapshot(result_wire_snapshot.encoded)
    captured_request = _capture_request_wire_snapshot(request)
    captured_result = _capture_result_wire_snapshot(result)
    exact_postcondition_snapshot = _require_consumed_postcondition_snapshot(
        postcondition_registry_snapshot,
        issuer=terminal_reauthentication_issuer,
        bridge_identity=bridge_identity,
    )
    current_postcondition_snapshot = _require_consumed_postcondition_snapshot(
        _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
            terminal_postcondition,
            issuer=terminal_reauthentication_issuer,
            bridge_identity=bridge_identity,
        ),
        issuer=terminal_reauthentication_issuer,
        bridge_identity=bridge_identity,
    )
    postcondition_projection = _postcondition_projection(current_postcondition_snapshot)
    issuer_binding_sha256 = cast(
        str,
        postcondition_projection["issuer_binding_sha256"],
    )
    read_only_configuration_sha256 = cast(
        str,
        postcondition_projection["read_only_configuration_sha256"],
    )
    if (
        stored_request != request_wire_snapshot
        or stored_result != result_wire_snapshot
        or captured_request != stored_request
        or captured_result != stored_result
        or expected_request != stored_request
        or stored_result.request != stored_request
        or not _same_consumed_postcondition_snapshot(
            exact_postcondition_snapshot,
            current_postcondition_snapshot,
        )
        or not _terminal_projection_matches(
            stored_result,
            current_postcondition_snapshot,
        )
    ):
        raise ValueError
    candidate = cast(
        TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation,
        object.__new__(
            cast(
                type[Any],
                TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation,
            )
        ),
    )
    fields = _composite_field_values(
        request=stored_request,
        result=stored_result,
        terminal_postcondition=current_postcondition_snapshot,
    )
    for name in _COMPOSITE_FIELDS:
        object.__setattr__(candidate, name, fields[name])
    values = _composite_values(candidate)
    _validate_composite_values(values)
    semantic_sha256 = hashlib.sha256(
        canonical_first_enrollment_json_bytes(_composite_payload(candidate))
    ).hexdigest()
    object.__setattr__(candidate, "_semantic_sha256", semantic_sha256)
    candidate_id = id(candidate)

    def candidate_lost(
        reference: weakref.ReferenceType[
            TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation
        ],
    ) -> None:
        if os.getpid() != _ORIGIN_PID:
            return
        with _COMPOSITE_REGISTRY_LOCK:
            current = _COMPOSITE_REGISTRY.get(candidate_id)
            if current is not None and current.reference is reference:
                _COMPOSITE_REGISTRY.pop(candidate_id, None)

    reference = weakref.ref(candidate, candidate_lost)
    registration = _CompositeRegistration(
        reference=reference,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
        values=values,
        semantic_sha256=semantic_sha256,
        loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
        retained_attempt=retained_attempt,
        retained_progress=retained_progress,
        request=request,
        result=result,
        terminal_postcondition=terminal_postcondition,
        terminal_reauthentication_issuer=terminal_reauthentication_issuer,
        bridge_identity=bridge_identity,
        authenticated_request_registration=authenticated_request_registration,
        source_identities=(
            loaded_decision_artifact_receipt,
            request_evidence_snapshot.receipt.consumed_identity,
            authenticated_request_registration,
            retained_attempt,
            retained_progress,
            request,
            result,
            terminal_postcondition,
            terminal_reauthentication_issuer,
            bridge_identity,
        ),
        request_evidence_snapshot=request_evidence_snapshot,
        request_wire_snapshot=stored_request,
        result_wire_snapshot=stored_result,
        postcondition_registry_snapshot=current_postcondition_snapshot,
        issuer_binding_sha256=issuer_binding_sha256,
        read_only_configuration_sha256=read_only_configuration_sha256,
    )
    if os.getpid() != _ORIGIN_PID:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor terminal observation is unavailable"
        )
    with _COMPOSITE_REGISTRY_LOCK:
        if candidate_id in _COMPOSITE_REGISTRY:
            raise ValueError
        _COMPOSITE_REGISTRY[candidate_id] = registration
    try:
        candidate.__post_init__()
    except BaseException:
        if os.getpid() == _ORIGIN_PID:
            with _COMPOSITE_REGISTRY_LOCK:
                if _COMPOSITE_REGISTRY.get(candidate_id) is registration:
                    _COMPOSITE_REGISTRY.pop(candidate_id, None)
        raise
    return candidate


def bind_post_enrollment_graceful_stop_operation_bound_terminal_observation(
    *,
    loaded_decision_artifact_receipt: (
        LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ),
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    artifact_directory: Path,
    ignored_root: Path,
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    operation_bound_result: TrustedTimeHeadAnchorOperationBoundCleanStopResult,
    terminal_postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    terminal_reauthentication_issuer: (
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    ),
) -> TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation:
    """Burn the authenticated request and ADR-0109 observation, then cross-bind them."""

    authenticated_request_registration: _AuthenticatedRequestRegistration | None = None
    try:
        authenticated_request_registration = _consume_authenticated_request_registration(
            request,
            loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
        )
        bridge_identity = authenticated_request_registration.bridge_identity
        postcondition_registry_snapshot = _require_consumed_postcondition_snapshot(
            _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                terminal_postcondition,
                issuer=terminal_reauthentication_issuer,
                bridge_identity=bridge_identity,
            ),
            issuer=terminal_reauthentication_issuer,
            bridge_identity=bridge_identity,
        )
        if (
            type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
            or type(operation_bound_result)
            is not TrustedTimeHeadAnchorOperationBoundCleanStopResult
            or type(terminal_postcondition)
            is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
            or type(terminal_reauthentication_issuer)
            is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
        ):
            raise ValueError
        if (
            authenticated_request_registration.request_evidence_snapshot.attempt.identity
            is not retained_attempt
            or authenticated_request_registration.request_evidence_snapshot.progress.identity
            is not retained_progress
        ):
            raise ValueError
        _validate_authenticated_request_registration_values(
            request,
            loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
            registration=authenticated_request_registration,
        )
        expected_request = authenticated_request_registration.request_wire_snapshot
        request_wire_snapshot = _capture_request_wire_snapshot(request)
        result_wire_snapshot = _capture_result_wire_snapshot(operation_bound_result)
        if (
            request_wire_snapshot != expected_request
            or result_wire_snapshot.request != request_wire_snapshot
            or not _terminal_projection_matches(
                result_wire_snapshot,
                postcondition_registry_snapshot,
            )
        ):
            raise ValueError
        exact_directory, exact_root = _exact_roots(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if (
            exact_directory != authenticated_request_registration.artifact_directory
            or exact_root != authenticated_request_registration.ignored_root
        ):
            raise ValueError
        final_snapshot = authenticated_request_registration.request_evidence_snapshot
        _require_snapshot_current(final_snapshot)
        _require_inspected_chain(
            final_snapshot,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
        )
        _require_snapshot_current(final_snapshot)
        if (
            _capture_request_wire_snapshot(_request_from_snapshot(final_snapshot))
            != request_wire_snapshot
        ):
            raise ValueError
        return _issue_composite(
            loaded_decision_artifact_receipt=loaded_decision_artifact_receipt,
            authenticated_request_registration=authenticated_request_registration,
            retained_attempt=retained_attempt,
            retained_progress=retained_progress,
            request=request,
            result=operation_bound_result,
            terminal_postcondition=terminal_postcondition,
            terminal_reauthentication_issuer=terminal_reauthentication_issuer,
            bridge_identity=bridge_identity,
            request_wire_snapshot=request_wire_snapshot,
            result_wire_snapshot=result_wire_snapshot,
            postcondition_registry_snapshot=postcondition_registry_snapshot,
        )
    except BaseException as error:
        request_cleanup_error: BaseException | None = None
        request_cleanup_transition_error: BaseException | None = None
        request_cleanup_retry_error: BaseException | None = None
        postcondition_cleanup_error: BaseException | None = None
        postcondition_cleanup_transition_error: BaseException | None = None
        postcondition_cleanup_retry_error: BaseException | None = None
        try:
            try:
                request_cleanup_error = _burn_authenticated_request_targets(
                    request,
                    loaded_decision_artifact_receipt=(loaded_decision_artifact_receipt),
                )
            except BaseException as observed_request_cleanup_error:
                request_cleanup_transition_error = observed_request_cleanup_error
        finally:
            try:
                request_cleanup_retry_error = _burn_authenticated_request_targets(
                    request,
                    loaded_decision_artifact_receipt=(loaded_decision_artifact_receipt),
                )
            except BaseException as observed_request_retry_error:
                request_cleanup_retry_error = observed_request_retry_error
        if authenticated_request_registration is not None:
            bridge_identity = authenticated_request_registration.bridge_identity
            try:
                try:
                    _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                        terminal_postcondition,
                        issuer=terminal_reauthentication_issuer,
                        bridge_identity=bridge_identity,
                    )
                except BaseException as observed_postcondition_cleanup_error:
                    postcondition_cleanup_error = observed_postcondition_cleanup_error
            except BaseException as observed_postcondition_transition_error:
                postcondition_cleanup_transition_error = observed_postcondition_transition_error
            finally:
                try:
                    _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                        terminal_postcondition,
                        issuer=terminal_reauthentication_issuer,
                        bridge_identity=bridge_identity,
                    )
                except BaseException as observed_postcondition_retry_error:
                    postcondition_cleanup_retry_error = observed_postcondition_retry_error
        terminal = _preferred_registry_exceptions(
            error,
            request_cleanup_transition_error,
            request_cleanup_error,
            request_cleanup_retry_error,
            postcondition_cleanup_transition_error,
            postcondition_cleanup_error,
            postcondition_cleanup_retry_error,
        )
        if terminal is not None and not isinstance(terminal, Exception):
            if terminal is error:
                raise
            raise terminal from error
        if isinstance(
            error,
            TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected,
        ):
            raise
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor terminal observation is unavailable"
        ) from None


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS",
    "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation",
    "TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected",
    "bind_post_enrollment_graceful_stop_operation_bound_terminal_observation",
    "build_post_enrollment_graceful_stop_supervisor_clean_stop_request",
]
