"""Inert host binding for one operation-bound graceful-stop terminal projection.

The request builder joins an exact process-local ADR-0106 receipt to the
publicly revalidated ADR-0110 attempt/progress chain.  The receipt digest is a
structural, unqualified input only: ADR-0106 has no durable receipt loader, so
this module does not claim historical authentication or provide a production
runtime caller.

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
    "phase6d-post-enrollment-graceful-stop-supervisor-bridge-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-supervisor-bridge"
)
POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS = (
    "operation_bound_terminal_projection_cross_bound_unqualified"
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
        "decision_artifact_receipt_authenticated",
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
        "historical_start_chain_authenticated",
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
    decision_artifact_receipt_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
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
    historical_start_chain_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
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
    identity: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    values: tuple[object, ...]
    encoded: bytes


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


def _capture_receipt_snapshot(
    value: object,
) -> _DecisionReceiptSnapshot:
    if type(value) is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
        raise ValueError
    value.__post_init__()
    encoded = canonical_first_enrollment_json_bytes(value.public_payload)
    values = _decode_receipt_identity_values(encoded)
    value.__post_init__()
    if tuple(getattr(value, name) for name in _DECISION_RECEIPT_IDENTITY_FIELDS) != values:
        raise ValueError
    return _DecisionReceiptSnapshot(identity=value, values=values, encoded=encoded)


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
    return _RequestEvidenceSnapshot(
        receipt=_capture_receipt_snapshot(decision_artifact_receipt),
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
    current = _capture_request_evidence_snapshot(
        decision_artifact_receipt=snapshot.receipt.identity,
        retained_attempt=snapshot.attempt.identity,
        retained_progress=snapshot.progress.identity,
    )
    if (
        current.receipt.identity is not snapshot.receipt.identity
        or current.receipt.values != snapshot.receipt.values
        or current.receipt.encoded != snapshot.receipt.encoded
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
        graceful_stop_decision_artifact_receipt_sha256=hashlib.sha256(
            snapshot.receipt.encoded
        ).hexdigest(),
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
    decision_artifact_receipt: object,
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
    decision_artifact_receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    artifact_directory: Path,
    ignored_root: Path,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    """Build one unqualified request from exact receipt and retained lifecycle evidence."""

    try:
        return _request_from_exact_evidence(
            decision_artifact_receipt=decision_artifact_receipt,
            retained_attempt=retained_attempt,
            retained_progress=retained_progress,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    except TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected(
            "trusted-time graceful-stop supervisor request is unavailable"
        ) from None


@dataclass(slots=True)
class _CompositeRegistration:
    reference: weakref.ReferenceType[
        TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation
    ]
    owner_pid: int
    owner_thread: threading.Thread
    values: tuple[object, ...]
    semantic_sha256: str
    decision_artifact_receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress
    request: TrustedTimeHeadAnchorOperationBoundCleanStopRequest
    result: TrustedTimeHeadAnchorOperationBoundCleanStopResult
    terminal_postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    terminal_reauthentication_issuer: (
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    )
    bridge_identity: _BridgeIdentity
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
            "exact_terminal_projection_cross_bound_unqualified": True,
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
            registration.decision_artifact_receipt,
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
            or type(registration.decision_artifact_receipt)
            is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
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
            or registration.request_evidence_snapshot.receipt.identity
            is not registration.decision_artifact_receipt
            or registration.request_evidence_snapshot.attempt.identity
            is not registration.retained_attempt
            or registration.request_evidence_snapshot.progress.identity
            is not registration.retained_progress
        ):
            raise ValueError
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
    TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
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
    decision_artifact_receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
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
        type(decision_artifact_receipt)
        is not TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
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
    request_evidence_snapshot = _capture_request_evidence_snapshot(
        decision_artifact_receipt=decision_artifact_receipt,
        retained_attempt=retained_attempt,
        retained_progress=retained_progress,
    )
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
        decision_artifact_receipt=decision_artifact_receipt,
        retained_attempt=retained_attempt,
        retained_progress=retained_progress,
        request=request,
        result=result,
        terminal_postcondition=terminal_postcondition,
        terminal_reauthentication_issuer=terminal_reauthentication_issuer,
        bridge_identity=bridge_identity,
        source_identities=(
            decision_artifact_receipt,
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
    decision_artifact_receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
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
    """Burn one ADR-0109 observation, then cross-bind all structural projections."""

    bridge_identity = _new_bridge_identity()
    try:
        postcondition_registry_snapshot = _require_consumed_postcondition_snapshot(
            _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                terminal_postcondition,
                issuer=terminal_reauthentication_issuer,
                bridge_identity=bridge_identity,
            ),
            issuer=terminal_reauthentication_issuer,
            bridge_identity=bridge_identity,
        )
        expected_request = _capture_request_wire_snapshot(
            _request_from_exact_evidence(
                decision_artifact_receipt=decision_artifact_receipt,
                retained_attempt=retained_attempt,
                retained_progress=retained_progress,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
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
        final_snapshot = _capture_request_evidence_snapshot(
            decision_artifact_receipt=decision_artifact_receipt,
            retained_attempt=retained_attempt,
            retained_progress=retained_progress,
        )
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
            decision_artifact_receipt=decision_artifact_receipt,
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
    except TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
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
