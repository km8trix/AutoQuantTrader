from __future__ import annotations

import base64
import hashlib

import pytest

from packages.domain.trusted_time_graceful_stop_v2 import (
    _FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    _authenticate_lifecycle_v2_transport_envelope_for_fake,
    canonical_v2_json_bytes,
    decode_lifecycle_v2_root,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    _FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    _PRODUCTION_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    CLEAN_STOP_ERROR_CONTRACT_VERSION,
    CLEAN_STOP_RESULT_CONTRACT_VERSION,
    LISTENER_PATH,
    SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
    SUPERVISOR_RAW_KEY_PATH,
    WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
    LifecycleV2AuthenticatedTerminalEnvelopeProof,
    LifecycleV2CleanStopError,
    LifecycleV2CleanStopResult,
    LifecycleV2SupervisorCleanupCommitment,
    LifecycleV2TerminalProjection,
    LifecycleV2TerminalWireEvidence,
    LifecycleV2WirePublicationReceipt,
    _mint_authenticated_lifecycle_v2_terminal_envelope_proof,
    _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof,
    validate_terminal_envelope_payload,
)

ENVIRONMENT = "test"
OPERATION_ID = "323e4567-e89b-42d3-a456-426614174099"
SUPERVISOR_ID = "1" * 64
SOURCE_ID = "2" * 64
NETWORK_ID = "3" * 64
UTC_TEXT = "2026-08-27T12:00:00.000000Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _root() -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        graceful_stop_target_sha256=_digest("target"),
        graceful_stop_decision_v1_sha256=_digest("decision"),
        graceful_stop_operator_attestation_envelope_sha256=_digest("attestation"),
        historical_decision_receipt_sha256=_digest("receipt"),
        admission_sha256=_digest("admission"),
        topology_sha256=_digest("topology"),
        topology_lease_sha256=_digest("topology-lease"),
        trusted_head_sha256=_digest("head"),
        stop_authority_sha256=_digest("authority"),
        transport_authority_manifest_sha256=_digest("manifest"),
        transport_key_generation=1,
        host_transport_key_id="host-key-1",
        supervisor_transport_key_id="supervisor-key-1",
        boot_epoch_sha256=_digest("boot"),
        host_process_epoch_sha256=_digest("host-process"),
        supervisor_process_epoch_sha256=_digest("supervisor-process"),
        channel_id=_digest("channel"),
        supervisor_container_id=SUPERVISOR_ID,
        source_container_id=SOURCE_ID,
        project_network_id=NETWORK_ID,
        chrony_command_socket_volume_identity_sha256=_digest("command-volume"),
        chrony_state_volume_identity_sha256=_digest("state-volume"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest]:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    intent = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=1,
        stage=LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
        predecessor_sha256=root.sha256,
        effect_kind="clean_stop_request",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "target_identity_sha256": root.supervisor_container_id,
                "arguments_sha256": basis.sha256,
                "admission_sha256": root.admission_sha256,
                "channel_id": root.channel_id,
                "call_deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )
    return root, LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)


def _terminal_projection() -> LifecycleV2TerminalProjection:
    value: dict[str, object] = {
        "request_sequence": 3,
        "request_scheduled_monotonic_ns": 10,
        "anchor_sequence": 3,
        "checkpoint_reason": "clean_stop",
        "confirmed_anchor_count": 3,
        "local_transition_count": 4,
        "confirmed_anchor_local_transition_ordinal": 4,
        "predecessor_anchor_sha256": _digest("predecessor"),
        "current_host_head_sha256": _digest("host-head"),
        "current_anchor_sha256": _digest("anchor"),
        "current_anchor_semantic_sha256": _digest("anchor-semantic"),
        "receipt_observed_at_utc": UTC_TEXT,
        "full_audit_completed": True,
        "prior_pending_intent_recovered": False,
        "uploaded_anchor_count": 1,
        "idempotent_duplicate_count": 0,
        "current_anchor_intent_semantic_sha256": _digest("intent-semantic"),
        "current_candidate_remote_readback_sha256": _digest("anchor"),
        "current_receipt_semantic_sha256": _digest("receipt-semantic"),
        "clean_stop_terminal_result_semantic_sha256": "0" * 64,
    }
    semantic_payload = {
        "anchor_sequence": value["anchor_sequence"],
        "checkpoint_reason": value["checkpoint_reason"],
        "confirmed_anchor_count": value["confirmed_anchor_count"],
        "confirmed_anchor_local_transition_ordinal": value[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "contract_version": "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1",
        "current_anchor_intent_semantic_sha256": value[
            "current_anchor_intent_semantic_sha256"
        ],
        "current_anchor_semantic_sha256": value["current_anchor_semantic_sha256"],
        "current_anchor_sha256": value["current_anchor_sha256"],
        "current_candidate_remote_readback_sha256": value[
            "current_candidate_remote_readback_sha256"
        ],
        "current_host_head_sha256": value["current_host_head_sha256"],
        "current_receipt_semantic_sha256": value["current_receipt_semantic_sha256"],
        "full_audit_completed": value["full_audit_completed"],
        "idempotent_duplicate_count": value["idempotent_duplicate_count"],
        "local_transition_count": value["local_transition_count"],
        "predecessor_anchor_sha256": value["predecessor_anchor_sha256"],
        "prior_pending_intent_recovered": value["prior_pending_intent_recovered"],
        "receipt_observed_at_utc": value["receipt_observed_at_utc"],
        "request_scheduled_monotonic_ns": value["request_scheduled_monotonic_ns"],
        "request_sequence": value["request_sequence"],
        "status": "exact_current_new_record_clean_stop_completed",
        "uploaded_anchor_count": value["uploaded_anchor_count"],
    }
    value["clean_stop_terminal_result_semantic_sha256"] = hashlib.sha256(
        canonical_v2_json_bytes(semantic_payload, maximum_bytes=64 * 1_024)
    ).hexdigest()
    return LifecycleV2TerminalProjection.capture(value)


def _cleanup(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2SupervisorCleanupCommitment:
    return LifecycleV2SupervisorCleanupCommitment.capture(
        {
            "contract_version": SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "status": "supervisor_transport_cleanup_committed",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "admission_sha256": root.admission_sha256,
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "transport_authority_manifest_sha256": (
                root.transport_authority_manifest_sha256
            ),
            "key_generation": root.transport_key_generation,
            "supervisor_key_id": root.supervisor_transport_key_id,
            "supervisor_socket_identity_sha256": _digest("socket"),
            "supervisor_peer_credential_sha256": _digest("peer"),
            "listener_path": LISTENER_PATH,
            "listener_path_device": 1,
            "listener_path_inode": 2,
            "listener_fd_socket_inode": 3,
            "accepted_fd_socket_inode": 4,
            "raw_key_path": SUPERVISOR_RAW_KEY_PATH,
            "raw_key_device": 5,
            "raw_key_inode": 6,
            "supervisor_challenge_sha256": _digest("challenge"),
            "supervisor_process_nonce_sha256": _digest("nonce"),
            "cleanup_deadline_boottime_ns": request.to_dict()[
                "transport_cleanup_deadline_boottime_ns"
            ],
        }
    )


def _result() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest, LifecycleV2CleanStopResult]:
    root, request = _request()
    projection = _terminal_projection()
    cleanup = _cleanup(root, request)
    request_fields = request.to_dict()
    return root, request, LifecycleV2CleanStopResult.capture(
        {
            "contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "exact_operation_bound_new_record_clean_stop_correlated_unqualified",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "admission_sha256": root.admission_sha256,
            "lifecycle_dispatch_prefix_sha256": request_fields[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "operation_bound_request": request_fields,
            "request_sha256": request.sha256,
            "terminal_projection": projection.to_dict(),
            "terminal_projection_sha256": projection.sha256,
            "supervisor_transport_cleanup_commitment": cleanup.to_dict(),
            "supervisor_transport_cleanup_commitment_sha256": cleanup.sha256,
            "result_completed_boottime_ns": root.admission_started_boottime_ns + 1,
            "transport_cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
    )


def _error() -> tuple[LifecycleV2Root, LifecycleV2CleanStopRequest, LifecycleV2CleanStopError]:
    root, request = _request()
    cleanup = _cleanup(root, request)
    request_fields = request.to_dict()
    return root, request, LifecycleV2CleanStopError.capture(
        {
            "contract_version": CLEAN_STOP_ERROR_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "operation_bound_clean_stop_failed_unqualified",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "request_sha256": request.sha256,
            "admission_sha256": root.admission_sha256,
            "lifecycle_dispatch_prefix_sha256": request_fields[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "error_code": "clean_stop_failed",
            "failure_boundary": "during_or_after_selection",
            "call_may_have_occurred": True,
            "retryable": False,
            "observed_boottime_ns": root.admission_started_boottime_ns + 1,
            "supervisor_transport_cleanup_commitment": cleanup.to_dict(),
            "supervisor_transport_cleanup_commitment_sha256": cleanup.sha256,
            "transport_cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        },
        request=request,
    )


def _envelope(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    *,
    frame_type: str,
    payload: bytes,
) -> UnverifiedLifecycleV2TransportEnvelope:
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": "supervisor_to_host",
            "frame_type": frame_type,
            "payload_contract_version": (
                CLEAN_STOP_RESULT_CONTRACT_VERSION
                if frame_type == "clean_stop_result"
                else CLEAN_STOP_ERROR_CONTRACT_VERSION
            ),
            "key_generation": root.transport_key_generation,
            "signing_key_id": root.supervisor_transport_key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": request.to_dict()[
                "lifecycle_dispatch_prefix_sha256"
            ],
            "message_counter": 1,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _publication_receipt_value(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    *,
    publication_authorized_boottime_ns: int,
) -> dict[str, object]:
    kind = "result" if envelope.frame_type == "clean_stop_result" else "error"
    file_name = (
        "trusted-time-post-enrollment-graceful-stop-v2-wire-"
        f"{kind}-{envelope.sha256}.json"
    )
    return {
        "contract_version": WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
        "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
        "status": "wire_envelope_published",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "artifact_kind": f"signed_{kind}_envelope",
        "artifact_directory_path": "/injected/adr0121/trusted-time",
        "artifact_directory_device": 1,
        "artifact_directory_inode": 2,
        "artifact_path": f"/injected/adr0121/trusted-time/{file_name}",
        "file_name": file_name,
        "file_device": 1,
        "file_inode": 3,
        "file_mode": 384,
        "file_size": len(envelope.encoded),
        "signed_envelope_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": envelope.frame_type,
        "payload_contract_version": envelope.to_dict()["payload_contract_version"],
        "payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "signature_sha256": envelope.signature_sha256,
        "key_generation": root.transport_key_generation,
        "signing_key_id": root.supervisor_transport_key_id,
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": request.to_dict()[
            "lifecycle_dispatch_prefix_sha256"
        ],
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "directory_fsync_completed": True,
        "stable_readback_completed": True,
        "publication_authorized_boottime_ns": publication_authorized_boottime_ns,
    }


def _proof(
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    root: LifecycleV2Root,
) -> LifecycleV2AuthenticatedTerminalEnvelopeProof:
    authenticated = _authenticate_lifecycle_v2_transport_envelope_for_fake(
        envelope,
        capability=_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    )
    return _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof(
        authenticated,
        root=root,
        capability=_FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    )


def _receipt(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    proof: LifecycleV2AuthenticatedTerminalEnvelopeProof,
) -> LifecycleV2WirePublicationReceipt:
    return LifecycleV2WirePublicationReceipt.capture(
        _publication_receipt_value(
            root,
            request,
            envelope,
            publication_authorized_boottime_ns=root.admission_started_boottime_ns + 3,
        ),
        proof=proof,
        request=request,
        root=root,
    )


def _result_evidence_value(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    result: LifecycleV2CleanStopResult,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    receipt: LifecycleV2WirePublicationReceipt,
) -> dict[str, object]:
    receipt_fields = receipt.to_dict()
    return {
        "intent_sha256": request.to_dict()["request_intent_sha256"],
        "responder_identity_sha256": root.supervisor_process_epoch_sha256,
        "disposition": "authenticated_result",
        "clean_stop_result_artifact_path": receipt_fields["artifact_path"],
        "clean_stop_result_artifact_name": receipt_fields["file_name"],
        "clean_stop_result_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": "clean_stop_result",
        "payload_contract_version": envelope.to_dict()["payload_contract_version"],
        "clean_stop_result_payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "clean_stop_result_signature_sha256": envelope.signature_sha256,
        "terminal_projection_sha256": result.terminal_projection.sha256,
        "key_generation": root.transport_key_generation,
        "signing_key_id": root.supervisor_transport_key_id,
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": request.to_dict()[
            "lifecycle_dispatch_prefix_sha256"
        ],
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "wire_publication_receipt": receipt_fields,
        "wire_publication_receipt_sha256": receipt.sha256,
        "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
        "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
    }


def test_terminal_proof_is_sealed_and_raw_wire_cannot_cross_either_mint() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    receipt_value = _publication_receipt_value(
        root,
        request,
        envelope,
        publication_authorized_boottime_ns=root.admission_started_boottime_ns + 3,
    )
    with pytest.raises(TypeError):
        LifecycleV2AuthenticatedTerminalEnvelopeProof()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof(
            envelope,
            root=root,
            capability=_FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
        )

    def unwrap_raw(
        value: object,
    ) -> tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]:
        if type(value) is not UnverifiedLifecycleV2TransportEnvelope:
            raise AssertionError("test unwrapper received another type")
        return value, root.transport_authority_manifest_sha256, "supervisor"

    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _mint_authenticated_lifecycle_v2_terminal_envelope_proof(
            envelope,
            unwrap=unwrap_raw,
            capability=_PRODUCTION_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2WirePublicationReceipt.capture(
            receipt_value,
            proof=envelope,  # type: ignore[arg-type]
            request=request,
            root=root,
        )


def test_fake_terminal_proof_requires_its_private_capability() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    authenticated = _authenticate_lifecycle_v2_transport_envelope_for_fake(
        envelope,
        capability=_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof(
            authenticated,
            root=root,
            capability=object(),
        )
    proof = _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof(
        authenticated,
        root=root,
        capability=_FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    )
    assert proof.envelope == envelope


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("environment", "other"),
        ("key_generation", 2),
        ("signing_key_id", "supervisor-key-2"),
        ("boot_epoch_sha256", "a" * 64),
        ("host_process_epoch_sha256", "b" * 64),
        ("supervisor_process_epoch_sha256", "c" * 64),
        ("channel_id", "d" * 64),
        ("lifecycle_dispatch_prefix_sha256", "e" * 64),
        ("deadline_boottime_ns", 1_121_000_000_001),
    ],
)
def test_receipt_rejects_every_cross_root_envelope_correlator(
    name: str,
    replacement: object,
) -> None:
    root, request, result = _result()
    envelope_value = _envelope(
        root,
        request,
        frame_type="clean_stop_result",
        payload=result.encoded,
    ).to_dict()
    envelope_value[name] = replacement
    envelope = UnverifiedLifecycleV2TransportEnvelope.capture(envelope_value)
    proof = _proof(envelope, root)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _receipt(root, request, envelope, proof)


def test_receipt_rejects_cross_manifest_proof() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    other_root_value = root.to_dict()
    other_root_value["transport_authority_manifest_sha256"] = "f" * 64
    other_root = decode_lifecycle_v2_root(
        canonical_v2_json_bytes(other_root_value, maximum_bytes=64 * 1_024)
    )
    proof = _proof(envelope, other_root)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _receipt(root, request, envelope, proof)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("transport_authority_manifest_sha256", "a" * 64),
        ("key_generation", 2),
        ("supervisor_key_id", "supervisor-key-2"),
        ("channel_id", "b" * 64),
        ("boot_epoch_sha256", "c" * 64),
        ("supervisor_process_epoch_sha256", "d" * 64),
        ("cleanup_deadline_boottime_ns", 421_000_000_001),
    ],
)
def test_receipt_rejects_every_cross_root_cleanup_correlator(
    name: str,
    replacement: object,
) -> None:
    root, request, result = _result()
    value = result.to_dict()
    cleanup_value = value["supervisor_transport_cleanup_commitment"]
    assert type(cleanup_value) is dict
    cleanup_value[name] = replacement
    cleanup = LifecycleV2SupervisorCleanupCommitment.capture(cleanup_value)
    value["supervisor_transport_cleanup_commitment"] = cleanup.to_dict()
    value["supervisor_transport_cleanup_commitment_sha256"] = cleanup.sha256
    if name == "channel_id":
        value["channel_id"] = replacement
        request_value = value["operation_bound_request"]
        assert type(request_value) is dict
        request_value["channel_id"] = replacement
        value["request_sha256"] = LifecycleV2CleanStopRequest.capture(request_value).sha256
    elif name == "boot_epoch_sha256":
        value["boot_epoch_sha256"] = replacement
        request_value = value["operation_bound_request"]
        assert type(request_value) is dict
        request_value["boot_epoch_sha256"] = replacement
        value["request_sha256"] = LifecycleV2CleanStopRequest.capture(request_value).sha256
    elif name == "supervisor_process_epoch_sha256":
        value["supervisor_process_epoch_sha256"] = replacement
        request_value = value["operation_bound_request"]
        assert type(request_value) is dict
        request_value["supervisor_process_epoch_sha256"] = replacement
        value["request_sha256"] = LifecycleV2CleanStopRequest.capture(request_value).sha256
    elif name == "cleanup_deadline_boottime_ns":
        value["transport_cleanup_deadline_boottime_ns"] = replacement
        request_value = value["operation_bound_request"]
        assert type(request_value) is dict
        request_value["transport_cleanup_deadline_boottime_ns"] = replacement
        assert type(replacement) is int
        request_value["clean_stop_result_deadline_boottime_ns"] = (
            replacement - 5_000_000_000
        )
        value["request_sha256"] = LifecycleV2CleanStopRequest.capture(request_value).sha256
    terminal = LifecycleV2CleanStopResult.capture(value)
    envelope = _envelope(
        root,
        request,
        frame_type="clean_stop_result",
        payload=terminal.encoded,
    )
    proof = _proof(envelope, root)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        _receipt(root, request, envelope, proof)


def test_result_payload_embedded_request_must_equal_supplied_request() -> None:
    root, request, result = _result()
    value = result.to_dict()
    embedded = value["operation_bound_request"]
    assert type(embedded) is dict
    embedded["request_intent_sha256"] = "a" * 64
    embedded["lifecycle_dispatch_prefix_sha256"] = "b" * 64
    crossed_request = LifecycleV2CleanStopRequest.capture(embedded)
    value["operation_bound_request"] = crossed_request.to_dict()
    value["request_sha256"] = crossed_request.sha256
    value["lifecycle_dispatch_prefix_sha256"] = crossed_request.to_dict()[
        "lifecycle_dispatch_prefix_sha256"
    ]
    crossed_result = LifecycleV2CleanStopResult.capture(value)
    envelope = _envelope(
        root,
        request,
        frame_type="clean_stop_result",
        payload=crossed_result.encoded,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        validate_terminal_envelope_payload(envelope, request=request)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_error_observation_is_strictly_before_cleanup_deadline(offset: int) -> None:
    _, request, error = _error()
    value = error.to_dict()
    cleanup_deadline = request.to_dict()["transport_cleanup_deadline_boottime_ns"]
    assert type(cleanup_deadline) is int
    value["observed_boottime_ns"] = cleanup_deadline + offset
    if offset == -1:
        assert LifecycleV2CleanStopError.capture(value, request=request).to_dict() == value
    else:
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2CleanStopError.capture(value, request=request)


def test_receipt_and_ordinal_two_reject_boolean_counter_substitution_and_raw_proof() -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    proof = _proof(envelope, root)
    receipt_value = _publication_receipt_value(
        root,
        request,
        envelope,
        publication_authorized_boottime_ns=root.admission_started_boottime_ns + 3,
    )
    receipt_value["message_counter"] = True
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2WirePublicationReceipt.capture(
            receipt_value,
            proof=proof,
            request=request,
            root=root,
        )
    receipt_value["message_counter"] = 1
    receipt = LifecycleV2WirePublicationReceipt.capture(
        receipt_value,
        proof=proof,
        request=request,
        root=root,
    )
    evidence_value = _result_evidence_value(root, request, result, envelope, receipt)
    assert (
        LifecycleV2TerminalWireEvidence.capture(
            evidence_value,
            proof=proof,
            request=request,
            root=root,
            responder_identity_sha256=root.supervisor_process_epoch_sha256,
        ).receipt
        == receipt
    )
    evidence_value["message_counter"] = True
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2TerminalWireEvidence.capture(
            evidence_value,
            proof=proof,
            request=request,
            root=root,
            responder_identity_sha256=root.supervisor_process_epoch_sha256,
        )
    evidence_value["message_counter"] = 1
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2TerminalWireEvidence.capture(
            evidence_value,
            proof=envelope,  # type: ignore[arg-type]
            request=request,
            root=root,
            responder_identity_sha256=root.supervisor_process_epoch_sha256,
        )


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("key_generation", 2),
        ("signing_key_id", "supervisor-key-2"),
        ("channel_id", "a" * 64),
        ("lifecycle_dispatch_prefix_sha256", "b" * 64),
        ("deadline_boottime_ns", 1_121_000_000_001),
    ],
)
def test_ordinal_two_rebinds_every_repeated_wire_correlator(
    name: str,
    replacement: object,
) -> None:
    root, request, result = _result()
    envelope = _envelope(root, request, frame_type="clean_stop_result", payload=result.encoded)
    proof = _proof(envelope, root)
    receipt = _receipt(root, request, envelope, proof)
    value = _result_evidence_value(root, request, result, envelope, receipt)
    value[name] = replacement
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2TerminalWireEvidence.capture(
            value,
            proof=proof,
            request=request,
            root=root,
            responder_identity_sha256=root.supervisor_process_epoch_sha256,
        )
