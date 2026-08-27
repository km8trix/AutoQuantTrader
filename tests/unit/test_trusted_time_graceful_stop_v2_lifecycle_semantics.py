from __future__ import annotations

import base64
import copy
import hashlib
import os
import pickle
import threading
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

import packages.domain.trusted_time_graceful_stop_v2_docker as docker_semantics_module
import packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics as lifecycle_module
import packages.domain.trusted_time_graceful_stop_v2_terminal as terminal_semantics_module
from packages.domain.trusted_time_graceful_stop_v2 import (
    _FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    LifecycleV2TranscriptEntry,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    _authenticate_lifecycle_v2_transport_envelope_for_fake,
    canonical_v2_json_bytes,
)
from packages.domain.trusted_time_graceful_stop_v2_docker import (
    DockerAdmissionCapture,
    DockerAdmissionRootedTracePrefix,
    DockerMutationResultSemantic,
    DockerOrdinalEvidence,
    DockerPlanIdentity,
    DockerVolumePreservationResult,
    TrustedTimeDockerEvidenceRejected,
)
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    HOST_RAW_KEY_PATH,
    HOST_SECRET_MOUNT_PATH,
    LIFECYCLE_V2_CLEANUP_SERVICE,
    SUPERVISOR_SECRET_MOUNT_PATH,
    TRANSPORT_MOUNT_PATH,
    LifecycleV2AuthenticatedReauthenticationBinding,
    LifecycleV2EmptySecretMountIdentity,
    LifecycleV2EmptySecretMountProjection,
    LifecycleV2HostTransportCleanupIdentity,
    LifecycleV2HostTransportCleanupReceipt,
    LifecycleV2InjectedCleanupObserver,
    LifecycleV2NativeOwnerCleanupReceipt,
    LifecycleV2NativeOwnerSet,
    LifecycleV2NormalProgressLineage,
    LifecycleV2PathAbsence,
    LifecycleV2ReauthenticationIntent,
    LifecycleV2SecretMountUnmountReceipt,
    LifecycleV2SupervisorQuiescenceObservation,
    LifecycleV2TransportCleanupPlan,
    LifecycleV2TransportQuiescence,
    TrustedTimeLifecycleV2SemanticsRejected,
    _build_injected_fake_lifecycle_v2_cleanup_observer,
    _mint_fake_lifecycle_v2_reauthentication_binding,
    consume_exact_lifecycle_v2_confirmed_success_lineage,
    consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository,
    lifecycle_v2_semantics_non_authority_facts,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_5,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_19,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    _FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    CLEAN_STOP_RESULT_CONTRACT_VERSION,
    LISTENER_PATH,
    SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
    SUPERVISOR_RAW_KEY_PATH,
    WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
    LifecycleV2CleanStopResult,
    LifecycleV2SupervisorCleanupCommitment,
    LifecycleV2TerminalProjection,
    LifecycleV2TerminalWireEvidence,
    LifecycleV2WirePublicationReceipt,
    _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof,
)
from tests.unit.trusted_time_graceful_stop_v2_docker_fakes import (
    FakeDockerDaemon,
    FakeDockerHttpAdapter,
)

ENVIRONMENT = "test"
OPERATION_ID = "423e4567-e89b-42d3-a456-426614174099"
CHANNEL_ID = "4" * 64
SUPERVISOR_ID = "1" * 64
SOURCE_ID = "2" * 64
NETWORK_ID = "3" * 64
PLAN_IDENTITY = DockerPlanIdentity(SUPERVISOR_ID, SOURCE_ID, NETWORK_ID)
UTC_TEXT = "2026-08-27T12:00:00.000000Z"
PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS = 120_000_000_030
POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS = 120_001_001_705


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _docker_evidence() -> tuple[
    FakeDockerDaemon,
    tuple[DockerOrdinalEvidence, ...],
    DockerAdmissionCapture,
]:
    daemon = FakeDockerDaemon(PLAN_IDENTITY)
    adapter = FakeDockerHttpAdapter(
        daemon,
        PLAN_IDENTITY,
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
    )
    entries = adapter.run_complete_plan()
    admission = DockerAdmissionCapture.from_prefix(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        channel_id=CHANNEL_ID,
        entries=entries[:6],
    )
    return daemon, entries, admission


def _trace_prefix(
    admission: DockerAdmissionCapture,
    entries: tuple[DockerOrdinalEvidence, ...],
    last_ordinal: int,
) -> DockerAdmissionRootedTracePrefix:
    result = DockerAdmissionRootedTracePrefix.from_admission(
        admission=admission,
        entries=entries[:6],
    )
    for entry in entries[6 : last_ordinal + 1]:
        result = result.append(entry)
    return result


def _root(admission: DockerAdmissionCapture) -> LifecycleV2Root:
    admission_fields = admission.to_dict()
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
        channel_id=CHANNEL_ID,
        supervisor_container_id=SUPERVISOR_ID,
        source_container_id=SOURCE_ID,
        project_network_id=NETWORK_ID,
        chrony_command_socket_volume_identity_sha256=cast(
            str, admission_fields["command_socket_volume_projection_sha256"]
        ),
        chrony_state_volume_identity_sha256=cast(
            str, admission_fields["state_volume_projection_sha256"]
        ),
        admission_started_boottime_ns=0,
        clean_stop_result_deadline_boottime_ns=120_000_000_000,
        operation_deadline_boottime_ns=600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request(
    root: LifecycleV2Root,
) -> tuple[LifecycleV2ProgressRecord, LifecycleV2CleanStopRequest]:
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
    return intent, LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)


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
    semantic = {
        "anchor_sequence": value["anchor_sequence"],
        "checkpoint_reason": value["checkpoint_reason"],
        "confirmed_anchor_count": value["confirmed_anchor_count"],
        "confirmed_anchor_local_transition_ordinal": value[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "contract_version": "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1",
        "current_anchor_intent_semantic_sha256": value["current_anchor_intent_semantic_sha256"],
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
        canonical_v2_json_bytes(semantic, maximum_bytes=64 * 1_024)
    ).hexdigest()
    return LifecycleV2TerminalProjection.capture(value)


def _cleanup_commitment(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2SupervisorCleanupCommitment:
    cleanup_deadline = request.to_dict()["transport_cleanup_deadline_boottime_ns"]
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
            "transport_authority_manifest_sha256": root.transport_authority_manifest_sha256,
            "key_generation": root.transport_key_generation,
            "supervisor_key_id": root.supervisor_transport_key_id,
            "supervisor_socket_identity_sha256": _digest("supervisor-socket"),
            "supervisor_peer_credential_sha256": _digest("supervisor-peer"),
            "listener_path": LISTENER_PATH,
            "listener_path_device": 1,
            "listener_path_inode": 2,
            "listener_fd_socket_inode": 3,
            "accepted_fd_socket_inode": 4,
            "raw_key_path": SUPERVISOR_RAW_KEY_PATH,
            "raw_key_device": 5,
            "raw_key_inode": 6,
            "supervisor_challenge_sha256": _digest("supervisor-challenge"),
            "supervisor_process_nonce_sha256": _digest("supervisor-nonce"),
            "cleanup_deadline_boottime_ns": cleanup_deadline,
        }
    )


def _clean_stop_result(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2CleanStopResult:
    projection = _terminal_projection()
    cleanup = _cleanup_commitment(root, request)
    request_fields = request.to_dict()
    return LifecycleV2CleanStopResult.capture(
        {
            "contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "exact_operation_bound_new_record_clean_stop_correlated_unqualified",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "admission_sha256": root.admission_sha256,
            "lifecycle_dispatch_prefix_sha256": request_fields["lifecycle_dispatch_prefix_sha256"],
            "channel_id": root.channel_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "supervisor_container_id": root.supervisor_container_id,
            "operation_bound_request": request.to_dict(),
            "request_sha256": request.sha256,
            "terminal_projection": projection.to_dict(),
            "terminal_projection_sha256": projection.sha256,
            "supervisor_transport_cleanup_commitment": cleanup.to_dict(),
            "supervisor_transport_cleanup_commitment_sha256": cleanup.sha256,
            "result_completed_boottime_ns": 10,
            "transport_cleanup_deadline_boottime_ns": request_fields[
                "transport_cleanup_deadline_boottime_ns"
            ],
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
    )


def _terminal_wire(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    result: LifecycleV2CleanStopResult,
) -> LifecycleV2TerminalWireEvidence:
    envelope = UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": "supervisor_to_host",
            "frame_type": "clean_stop_result",
            "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
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
            "payload_sha256": hashlib.sha256(result.encoded).hexdigest(),
            "payload_base64": base64.b64encode(result.encoded).decode("ascii"),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )
    authenticated = _authenticate_lifecycle_v2_transport_envelope_for_fake(
        envelope,
        capability=_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    )
    proof = _mint_fake_authenticated_lifecycle_v2_terminal_envelope_proof(
        authenticated,
        root=root,
        capability=_FAKE_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    )
    file_name = f"trusted-time-post-enrollment-graceful-stop-v2-wire-result-{envelope.sha256}.json"
    receipt = LifecycleV2WirePublicationReceipt.capture(
        {
            "contract_version": WIRE_PUBLICATION_RECEIPT_CONTRACT_VERSION,
            "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
            "status": "wire_envelope_published",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "artifact_kind": "signed_result_envelope",
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
            "frame_type": "clean_stop_result",
            "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "payload_sha256": hashlib.sha256(result.encoded).hexdigest(),
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
            "publication_authorized_boottime_ns": 13,
        },
        proof=proof,
        request=request,
        root=root,
    )
    return LifecycleV2TerminalWireEvidence.capture(
        {
            "intent_sha256": request.to_dict()["request_intent_sha256"],
            "responder_identity_sha256": root.supervisor_process_epoch_sha256,
            "disposition": "authenticated_result",
            "clean_stop_result_artifact_path": receipt.to_dict()["artifact_path"],
            "clean_stop_result_artifact_name": file_name,
            "clean_stop_result_sha256": envelope.sha256,
            "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "frame_type": "clean_stop_result",
            "payload_contract_version": CLEAN_STOP_RESULT_CONTRACT_VERSION,
            "clean_stop_result_payload_sha256": hashlib.sha256(result.encoded).hexdigest(),
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
            "wire_publication_receipt": receipt.to_dict(),
            "wire_publication_receipt_sha256": receipt.sha256,
            "call_started_boottime_ns": 11,
            "call_completed_boottime_ns": 12,
        },
        proof=proof,
        request=request,
        root=root,
        responder_identity_sha256=root.supervisor_process_epoch_sha256,
    )


@dataclass(frozen=True, slots=True)
class _Scenario:
    daemon: FakeDockerDaemon
    entries: tuple[DockerOrdinalEvidence, ...]
    admission: DockerAdmissionCapture
    root: LifecycleV2Root
    cleanup_observer: LifecycleV2InjectedCleanupObserver
    request_intent: LifecycleV2ProgressRecord
    clean_stop_result: LifecycleV2CleanStopResult
    terminal_wire: LifecycleV2TerminalWireEvidence
    result_record: LifecycleV2ProgressRecord
    lineage: LifecycleV2NormalProgressLineage


def _scenario() -> _Scenario:
    daemon, entries, admission = _docker_evidence()
    root = _root(admission)
    cleanup_observer = _build_injected_fake_lifecycle_v2_cleanup_observer(
        root=root,
        observer_nonce_sha256=_digest("cleanup-observer"),
    )
    request_intent, request = _request(root)
    result = _clean_stop_result(root, request)
    wire = _terminal_wire(root, request, result)
    result_record = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=2,
        stage=LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        predecessor_sha256=request_intent.sha256,
        effect_kind="clean_stop_result",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(wire.to_dict()),
        recorded_at_utc=UTC_TEXT,
    )
    lineage = LifecycleV2NormalProgressLineage.from_retained_result(
        root=root,
        result_record=result_record,
        terminal_wire_evidence=wire,
        clean_stop_result=result,
    )
    return _Scenario(
        daemon,
        entries,
        admission,
        root,
        cleanup_observer,
        request_intent,
        result,
        wire,
        result_record,
        lineage,
    )


def _transport_plan(scenario: _Scenario) -> LifecycleV2TransportCleanupPlan:
    host_identity = LifecycleV2HostTransportCleanupIdentity.capture(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        host_socket_identity_sha256=_digest("host-socket"),
        host_peer_credential_sha256=_digest("host-peer"),
        host_raw_key_device=7,
        host_raw_key_inode=8,
        host_challenge_sha256=_digest("host-challenge"),
        host_process_nonce_sha256=_digest("host-nonce"),
    )
    return LifecycleV2TransportCleanupPlan.from_retained_result(
        root=scenario.root,
        result_record=scenario.result_record,
        terminal_wire_evidence=scenario.terminal_wire,
        clean_stop_result=scenario.clean_stop_result,
        host_identity=host_identity,
    )


def _transport_quiescence(
    scenario: _Scenario,
    plan: LifecycleV2TransportCleanupPlan,
    record_three: LifecycleV2ProgressRecord,
) -> LifecycleV2TransportQuiescence:
    commitment = plan.supervisor_commitment.to_dict()
    observation = LifecycleV2SupervisorQuiescenceObservation.capture(
        {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-supervisor-transport-quiescence-observation-v2"
            ),
            "service": LIFECYCLE_V2_CLEANUP_SERVICE,
            "status": "supervisor_transport_quiescence_observed",
            "environment": scenario.root.environment,
            "graceful_stop_operation_id": scenario.root.graceful_stop_operation_id,
            "lifecycle_root_sha256": scenario.root.sha256,
            "channel_id": scenario.root.channel_id,
            "supervisor_process_epoch_sha256": scenario.root.supervisor_process_epoch_sha256,
            "supervisor_cleanup_commitment_sha256": plan.supervisor_commitment.sha256,
            "supervisor_peer_credential_sha256": commitment["supervisor_peer_credential_sha256"],
            "listener_path": LISTENER_PATH,
            "listener_path_device": commitment["listener_path_device"],
            "listener_path_inode": commitment["listener_path_inode"],
            "listener_fd_socket_inode": commitment["listener_fd_socket_inode"],
            "accepted_fd_socket_inode": commitment["accepted_fd_socket_inode"],
            "supervisor_fd_table_sha256": _digest("fd-table"),
            "channel_eof_observed": True,
            "listener_fd_absent": True,
            "accepted_fd_absent": True,
            "socket_path_absent": True,
            "credential_path_absent": True,
            "observed_boottime_ns": 25,
        },
        root=scenario.root,
        plan=plan,
        observer=scenario.cleanup_observer,
    )
    receipt = LifecycleV2HostTransportCleanupReceipt.capture(
        {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-host-transport-cleanup-receipt-v2"
            ),
            "service": LIFECYCLE_V2_CLEANUP_SERVICE,
            "status": "host_transport_cleanup_completed",
            "environment": scenario.root.environment,
            "graceful_stop_operation_id": scenario.root.graceful_stop_operation_id,
            "lifecycle_root_sha256": scenario.root.sha256,
            "channel_id": scenario.root.channel_id,
            "host_process_epoch_sha256": scenario.root.host_process_epoch_sha256,
            "host_socket_identity_sha256": _digest("host-socket"),
            "host_peer_credential_sha256": _digest("host-peer"),
            "host_raw_key_path": HOST_RAW_KEY_PATH,
            "host_raw_key_device": 7,
            "host_raw_key_inode": 8,
            "accepted_channel_closed": True,
            "host_signer_zeroized": True,
            "host_challenge_zeroized": True,
            "host_process_nonce_zeroized": True,
            "credential_path_absent": True,
            "cleanup_started_boottime_ns": 26,
            "cleanup_completed_boottime_ns": 30,
        },
        root=scenario.root,
        plan=plan,
        observer=scenario.cleanup_observer,
    )
    return LifecycleV2TransportQuiescence.confirm(
        root=scenario.root,
        cleanup_record=record_three,
        plan=plan,
        observation=observation,
        host_receipt=receipt,
    )


def _binding(
    root: LifecycleV2Root,
    intent: LifecycleV2ReauthenticationIntent,
    *,
    issuer: str,
    challenge: str,
    observation: str,
    started: int,
    completed: int,
) -> LifecycleV2AuthenticatedReauthenticationBinding:
    boundary = intent.boundary
    return _mint_fake_lifecycle_v2_reauthentication_binding(
        {
            "contract_version": (
                "phase6d-trusted-time-graceful-stop-"
                f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
            ),
            "service": LIFECYCLE_V2_CLEANUP_SERVICE,
            "status": f"{boundary}_reauthentication_bound",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "lifecycle_root_sha256": root.sha256,
            "channel_id": root.channel_id,
            "boundary": boundary,
            "intent_semantic_sha256": intent.sha256,
            "issuer_identity_sha256": _digest(issuer),
            "challenge_sha256": _digest(challenge),
            "observation_semantic_sha256": _digest(observation),
            "observed_head_sha256": intent.to_dict()["expected_head_sha256"],
            "provider_identity_sha256": intent.to_dict()["provider_identity_sha256"],
            "observation_started_boottime_ns": started,
            "observation_completed_boottime_ns": completed,
        },
        root=root,
        intent=intent,
    )


def _prefix_transcript(
    scenario: _Scenario,
    lineage: LifecycleV2NormalProgressLineage,
) -> LifecycleV2Transcript:
    wire = scenario.terminal_wire.to_dict()
    entries = [
        LifecycleV2TranscriptEntry(
            ordinal=0,
            stage=LifecycleV2Stage.ROOT_RESERVED,
            record_artifact_kind="root",
            record_contract_version=LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
            record_artifact_sha256=scenario.root.sha256,
            predecessor_sha256=None,
        ),
        LifecycleV2TranscriptEntry(
            ordinal=1,
            stage=LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
            record_artifact_kind="progress",
            record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
            record_artifact_sha256=scenario.request_intent.sha256,
            predecessor_sha256=scenario.root.sha256,
        ),
        LifecycleV2TranscriptEntry(
            ordinal=2,
            stage=LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
            record_artifact_kind="progress",
            record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
            record_artifact_sha256=scenario.result_record.sha256,
            predecessor_sha256=scenario.request_intent.sha256,
            wire_artifact_kind="signed_result_envelope",
            wire_artifact_path=cast(str, wire["clean_stop_result_artifact_path"]),
            wire_artifact_file_name=cast(str, wire["clean_stop_result_artifact_name"]),
            wire_artifact_sha256=cast(str, wire["clean_stop_result_sha256"]),
        ),
    ]
    entries.extend(
        LifecycleV2TranscriptEntry(
            ordinal=record.ordinal,
            stage=record.stage,
            record_artifact_kind="progress",
            record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
            record_artifact_sha256=record.sha256,
            predecessor_sha256=record.predecessor_sha256,
        )
        for record in lineage.records
        if 3 <= record.ordinal <= 18
    )
    return LifecycleV2Transcript(
        environment=scenario.root.environment,
        graceful_stop_operation_id=scenario.root.graceful_stop_operation_id,
        root_sha256=scenario.root.sha256,
        entries=tuple(entries),
    )


def _mount(
    scenario: _Scenario,
    path: str,
    mount_id: int,
    *,
    observed_boottime_ns: int = 1_100_210,
) -> LifecycleV2EmptySecretMountIdentity:
    uid, gid, mode = {
        HOST_SECRET_MOUNT_PATH: (0, 0, 0o700),
        SUPERVISOR_SECRET_MOUNT_PATH: (0, 10_001, 0o730),
        TRANSPORT_MOUNT_PATH: (0, 10_001, 0o770),
    }[path]
    return LifecycleV2EmptySecretMountIdentity.capture(
        {
            "path": path,
            "mount_id": mount_id,
            "mount_parent_id": 1,
            "mount_major_minor": f"0:{mount_id}",
            "mount_root": "/",
            "mount_options": ["nodev", "noexec", "nosuid", "rw", "size=64K"],
            "directory_device": mount_id + 100,
            "directory_inode": mount_id + 200,
            "directory_uid": uid,
            "directory_gid": gid,
            "directory_mode": mode,
            "entry_count": 0,
        },
        observer=scenario.cleanup_observer,
        observed_boottime_ns=observed_boottime_ns,
    )


def _mounts(scenario: _Scenario) -> tuple[LifecycleV2EmptySecretMountIdentity, ...]:
    return (
        _mount(scenario, HOST_SECRET_MOUNT_PATH, 10),
        _mount(scenario, SUPERVISOR_SECRET_MOUNT_PATH, 11),
        _mount(scenario, TRANSPORT_MOUNT_PATH, 12),
    )


def _owners(
    root: LifecycleV2Root,
    observer: LifecycleV2InjectedCleanupObserver,
) -> LifecycleV2NativeOwnerSet:
    return LifecycleV2NativeOwnerSet.capture(
        root=root,
        observer=observer,
        owners=[
            {
                "owner_kind": kind,
                "owner_process_epoch_sha256": (
                    root.supervisor_process_epoch_sha256
                    if kind == "endpoint_signer"
                    else root.host_process_epoch_sha256
                ),
                "owner_nonce_sha256": _digest(f"owner-{kind}"),
            }
            for kind in (
                "docker_effect_client",
                "endpoint_signer",
                "post_teardown_issuer",
                "pre_effect_issuer",
                "transport_channel",
            )
        ],
        observed_boottime_ns=1_100_220,
    )


def _through_six(scenario: _Scenario) -> LifecycleV2NormalProgressLineage:
    plan = _transport_plan(scenario)
    lineage = scenario.lineage.retain_transport_cleanup_commitment(
        plan=plan, recorded_at_utc=UTC_TEXT
    )
    quiescence = _transport_quiescence(scenario, plan, lineage.last_record)
    lineage = lineage.confirm_transport_channel_quiesced(
        quiescence=quiescence, recorded_at_utc=UTC_TEXT
    )
    lineage = lineage.retain_pre_effect_reauthentication_intent(
        provider_identity_sha256=_digest("provider"),
        call_deadline_boottime_ns=PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS,
        recorded_at_utc=UTC_TEXT,
    )
    intent = cast(LifecycleV2ReauthenticationIntent, lineage.semantic_at(5))
    binding = _binding(
        scenario.root,
        intent,
        issuer="pre-issuer",
        challenge="pre-challenge",
        observation="pre-observation",
        started=100,
        completed=200,
    )
    return lineage.retain_pre_effect_reauthentication_binding(
        binding=binding, recorded_at_utc=UTC_TEXT
    )


def _through_eighteen(scenario: _Scenario) -> LifecycleV2NormalProgressLineage:
    lineage = _through_six(scenario)
    mutations = (
        (
            "retain_supervisor_container_stop_intent",
            "retain_supervisor_container_stop_result",
            "container_stop",
            6,
            1,
        ),
        (
            "retain_source_container_stop_intent",
            "retain_source_container_stop_result",
            "container_stop",
            8,
            2,
        ),
        (
            "retain_supervisor_container_remove_intent",
            "retain_supervisor_container_remove_result",
            "container_remove",
            10,
            1,
        ),
        (
            "retain_source_container_remove_intent",
            "retain_source_container_remove_result",
            "container_remove",
            12,
            2,
        ),
        (
            "retain_project_network_remove_intent",
            "retain_project_network_remove_result",
            "network_remove",
            14,
            3,
        ),
    )
    for intent_name, result_name, kind, ordinal, admitted_ordinal in mutations:
        prior = (
            _trace_prefix(scenario.admission, scenario.entries, ordinal - 1)
            if lineage.docker_trace is None
            else lineage.docker_trace
        )
        lineage = getattr(lineage, intent_name)(
            admission=scenario.admission,
            trace_prefix=prior,
            call_deadline_boottime_ns=2_000_000,
            recorded_at_utc=UTC_TEXT,
        )
        result_prefix = _trace_prefix(scenario.admission, scenario.entries, ordinal + 1)
        semantic = DockerMutationResultSemantic.from_pair(
            result_kind=kind,
            environment=ENVIRONMENT,
            graceful_stop_operation_id=OPERATION_ID,
            root_sha256=scenario.root.sha256,
            admission=scenario.admission,
            trace_prefix=result_prefix,
            admitted_target=scenario.entries[admitted_ordinal],
            previous=scenario.entries[ordinal - 1],
            primary=scenario.entries[ordinal],
            post_inspect=scenario.entries[ordinal + 1],
        )
        lineage = getattr(lineage, result_name)(
            result_semantic=semantic,
            trace_prefix=result_prefix,
            recorded_at_utc=UTC_TEXT,
        )
    lineage = lineage.retain_named_volume_preservation_intent(
        call_deadline_boottime_ns=2_000_000,
        recorded_at_utc=UTC_TEXT,
    )
    prefix = _trace_prefix(scenario.admission, scenario.entries, 17)
    volume = DockerVolumePreservationResult.from_pair(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=scenario.root.sha256,
        admission=scenario.admission,
        trace_prefix=prefix,
        previous=scenario.entries[15],
        command_socket=scenario.entries[16],
        state=scenario.entries[17],
        volume_delete_call_count=scenario.daemon.volume_delete_call_count,
    )
    return lineage.retain_named_volumes_preserved(
        result_semantic=volume,
        trace_prefix=prefix,
        recorded_at_utc=UTC_TEXT,
    )


def _through_twenty_one(
    scenario: _Scenario,
) -> tuple[
    LifecycleV2NormalProgressLineage,
    tuple[LifecycleV2EmptySecretMountIdentity, ...],
    LifecycleV2NativeOwnerSet,
]:
    lineage = _through_eighteen(scenario)
    transcript = _prefix_transcript(scenario, lineage)
    lineage = lineage.retain_post_teardown_reauthentication_intent(
        prefix_transcript=transcript,
        provider_identity_sha256=_digest("provider"),
        call_deadline_boottime_ns=POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS,
        recorded_at_utc=UTC_TEXT,
    )
    intent = cast(LifecycleV2ReauthenticationIntent, lineage.semantic_at(19))
    binding = _binding(
        scenario.root,
        intent,
        issuer="post-issuer",
        challenge="post-challenge",
        observation="post-observation",
        started=1_100_000,
        completed=1_100_100,
    )
    lineage = lineage.retain_post_teardown_reauthentication_binding(
        binding=binding,
        recorded_at_utc=UTC_TEXT,
    )
    mounts = _mounts(scenario)
    recovery = LifecycleV2PathAbsence.recovery_secret_mount(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        observed_boottime_ns=1_100_200,
    )
    socket = LifecycleV2PathAbsence.transport_socket(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        observed_boottime_ns=1_100_201,
    )
    credentials = LifecycleV2PathAbsence.credential_paths(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        observed_boottime_ns=1_100_202,
    )
    owners = _owners(scenario.root, scenario.cleanup_observer)
    lineage = lineage.retain_terminal_cleanup_intent(
        observer=scenario.cleanup_observer,
        mounts=mounts,
        recovery_secret_mount_absence=recovery,
        socket_path_absence=socket,
        credential_path_absence=credentials,
        native_owner_set=owners,
        cleanup_authorized_boottime_ns=1_100_250,
        recorded_at_utc=UTC_TEXT,
    )
    authorization = lineage.terminal_cleanup_authorization
    assert authorization is not None
    return lineage, mounts, owners


def _complete_lineage(scenario: _Scenario) -> LifecycleV2NormalProgressLineage:
    lineage, mounts, owners = _through_twenty_one(scenario)
    authorization = lineage.terminal_cleanup_authorization
    assert authorization is not None
    empty = LifecycleV2EmptySecretMountProjection.from_mounts(root=scenario.root, mounts=mounts)
    unmount = LifecycleV2SecretMountUnmountReceipt.completed(
        root=scenario.root,
        projection=empty,
        authorization=authorization,
        completed_boottime_ns=(1_100_300, 1_100_400, 1_100_500),
    )
    owner_receipt = LifecycleV2NativeOwnerCleanupReceipt.completed(
        root=scenario.root,
        owners=owners,
        authorization=authorization,
        completed_boottime_ns=1_100_600,
    )
    final_recovery = LifecycleV2PathAbsence.recovery_secret_mount(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_700,
    )
    final_socket = LifecycleV2PathAbsence.transport_socket(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_701,
    )
    final_credentials = LifecycleV2PathAbsence.credential_paths(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_702,
    )
    return lineage.retain_terminal_cleanup_confirmed(
        empty_mount_projection=empty,
        unmount_receipt=unmount,
        native_owner_cleanup_receipt=owner_receipt,
        recovery_secret_mount_absence=final_recovery,
        socket_absence=final_socket,
        credential_path_absence=final_credentials,
        recorded_at_utc=UTC_TEXT,
    )


def test_exact_normal_lineage_is_gap_free_and_fully_typed_through_ordinal_twenty_two() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)

    assert [record.ordinal for record in lineage.records] == list(range(2, 23))
    assert [record.stage for record in lineage.records] == [
        LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
        LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED,
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
        LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
        LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
        LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED,
        LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED,
    ]
    assert all(
        current.predecessor_sha256 == previous.sha256
        for previous, current in zip(lineage.records[:-1], lineage.records[1:], strict=True)
    )
    assert all(
        record.deadline_boottime_ns == scenario.root.operation_deadline_boottime_ns
        for record in lineage.records
    )
    assert lineage.record_at(22).evidence.to_dict()["all_private_material_unreachable"] is True
    assert scenario.daemon.volume_delete_call_count == 0


def test_named_builders_do_not_accept_caller_selected_stage_ordinal_predecessor_or_effect() -> None:
    scenario = _scenario()
    plan = _transport_plan(scenario)
    with pytest.raises(TypeError):
        LifecycleV2NormalProgressLineage(
            stage=LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED
        )
    with pytest.raises(TypeError):
        LifecycleV2TransportCleanupPlan(clean_stop_result_sha256="0" * 64)
    with pytest.raises(TypeError):
        scenario.lineage.retain_transport_cleanup_commitment(
            plan=plan,
            recorded_at_utc=UTC_TEXT,
            ordinal=4,
        )  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "field",
    [
        "channel_eof_observed",
        "listener_fd_absent",
        "accepted_fd_absent",
        "socket_path_absent",
        "credential_path_absent",
    ],
)
def test_supervisor_quiescence_rejects_every_false_cleanup_fact(field: str) -> None:
    scenario = _scenario()
    plan = _transport_plan(scenario)
    commitment = plan.supervisor_commitment.to_dict()
    value: dict[str, object] = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-supervisor-transport-quiescence-observation-v2"
        ),
        "service": LIFECYCLE_V2_CLEANUP_SERVICE,
        "status": "supervisor_transport_quiescence_observed",
        "environment": scenario.root.environment,
        "graceful_stop_operation_id": scenario.root.graceful_stop_operation_id,
        "lifecycle_root_sha256": scenario.root.sha256,
        "channel_id": scenario.root.channel_id,
        "supervisor_process_epoch_sha256": scenario.root.supervisor_process_epoch_sha256,
        "supervisor_cleanup_commitment_sha256": plan.supervisor_commitment.sha256,
        "supervisor_peer_credential_sha256": commitment["supervisor_peer_credential_sha256"],
        "listener_path": LISTENER_PATH,
        "listener_path_device": commitment["listener_path_device"],
        "listener_path_inode": commitment["listener_path_inode"],
        "listener_fd_socket_inode": commitment["listener_fd_socket_inode"],
        "accepted_fd_socket_inode": commitment["accepted_fd_socket_inode"],
        "supervisor_fd_table_sha256": _digest("fd-table"),
        "channel_eof_observed": True,
        "listener_fd_absent": True,
        "accepted_fd_absent": True,
        "socket_path_absent": True,
        "credential_path_absent": True,
        "observed_boottime_ns": 25,
    }
    value[field] = False
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2SupervisorQuiescenceObservation.capture(
            value,
            root=scenario.root,
            plan=plan,
            observer=scenario.cleanup_observer,
        )


def test_transport_cleanup_rejects_equality_deadline_path_and_owner_drift() -> None:
    scenario = _scenario()
    plan = _transport_plan(scenario)
    value = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-host-transport-cleanup-receipt-v2"
        ),
        "service": LIFECYCLE_V2_CLEANUP_SERVICE,
        "status": "host_transport_cleanup_completed",
        "environment": scenario.root.environment,
        "graceful_stop_operation_id": scenario.root.graceful_stop_operation_id,
        "lifecycle_root_sha256": scenario.root.sha256,
        "channel_id": scenario.root.channel_id,
        "host_process_epoch_sha256": scenario.root.host_process_epoch_sha256,
        "host_socket_identity_sha256": _digest("host-socket"),
        "host_peer_credential_sha256": _digest("host-peer"),
        "host_raw_key_path": HOST_RAW_KEY_PATH,
        "host_raw_key_device": 7,
        "host_raw_key_inode": 8,
        "accepted_channel_closed": True,
        "host_signer_zeroized": True,
        "host_challenge_zeroized": True,
        "host_process_nonce_zeroized": True,
        "credential_path_absent": True,
        "cleanup_started_boottime_ns": 20,
        "cleanup_completed_boottime_ns": plan.evidence.to_dict()["cleanup_deadline_boottime_ns"],
    }
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2HostTransportCleanupReceipt.capture(
            value,
            root=scenario.root,
            plan=plan,
            observer=scenario.cleanup_observer,
        )
    for field, replacement in (
        ("host_raw_key_path", "/tmp/key"),
        ("host_raw_key_inode", 9),
        ("accepted_channel_closed", False),
    ):
        changed = dict(value)
        changed["cleanup_completed_boottime_ns"] = 30
        changed[field] = replacement
        with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
            LifecycleV2HostTransportCleanupReceipt.capture(
                changed,
                root=scenario.root,
                plan=plan,
                observer=scenario.cleanup_observer,
            )


def test_docker_order_target_trace_and_result_deadline_are_closed() -> None:
    scenario = _scenario()
    lineage = _through_six(scenario)
    prefix = _trace_prefix(scenario.admission, scenario.entries, 5)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_source_container_stop_intent(
            admission=scenario.admission,
            trace_prefix=prefix,
            call_deadline_boottime_ns=2_000_000,
            recorded_at_utc=UTC_TEXT,
        )
    result_prefix = _trace_prefix(scenario.admission, scenario.entries, 7)
    semantic = DockerMutationResultSemantic.from_pair(
        result_kind="container_stop",
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=scenario.root.sha256,
        admission=scenario.admission,
        trace_prefix=result_prefix,
        admitted_target=scenario.entries[1],
        previous=scenario.entries[5],
        primary=scenario.entries[6],
        post_inspect=scenario.entries[7],
    )
    completed = cast(int, semantic.to_dict()["call_completed_boottime_ns"])
    lineage = lineage.retain_supervisor_container_stop_intent(
        admission=scenario.admission,
        trace_prefix=prefix,
        call_deadline_boottime_ns=completed,
        recorded_at_utc=UTC_TEXT,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_supervisor_container_stop_result(
            result_semantic=semantic,
            trace_prefix=result_prefix,
            recorded_at_utc=UTC_TEXT,
        )


def test_docker_result_rejects_cross_root_semantic_and_digest_only_substitute() -> None:
    scenario = _scenario()
    lineage = _through_six(scenario)
    prefix = _trace_prefix(scenario.admission, scenario.entries, 5)
    lineage = lineage.retain_supervisor_container_stop_intent(
        admission=scenario.admission,
        trace_prefix=prefix,
        call_deadline_boottime_ns=2_000_000,
        recorded_at_utc=UTC_TEXT,
    )
    result_prefix = _trace_prefix(scenario.admission, scenario.entries, 7)
    crossed = DockerMutationResultSemantic.from_pair(
        result_kind="container_stop",
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        root_sha256=_digest("other-root"),
        admission=scenario.admission,
        trace_prefix=result_prefix,
        admitted_target=scenario.entries[1],
        previous=scenario.entries[5],
        primary=scenario.entries[6],
        post_inspect=scenario.entries[7],
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_supervisor_container_stop_result(
            result_semantic=crossed,
            trace_prefix=result_prefix,
            recorded_at_utc=UTC_TEXT,
        )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_supervisor_container_stop_result(
            result_semantic=cast(Any, {"result_semantic_sha256": crossed.sha256}),
            trace_prefix=result_prefix,
            recorded_at_utc=UTC_TEXT,
        )


@pytest.mark.parametrize("entry_count", [False, True, 1])
def test_empty_mount_identity_rejects_false_bool_and_nonempty_projection(
    entry_count: object,
) -> None:
    scenario = _scenario()
    value = _mount(scenario, HOST_SECRET_MOUNT_PATH, 10).to_dict()
    value["entry_count"] = entry_count
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2EmptySecretMountIdentity.capture(
            value,
            observer=scenario.cleanup_observer,
            observed_boottime_ns=1_100_210,
        )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("directory_uid", False),
        ("directory_gid", False),
        ("directory_mode", True),
    ],
)
def test_empty_mount_identity_rejects_boolean_integer_substitution(
    field: str,
    replacement: object,
) -> None:
    scenario = _scenario()
    value = _mount(scenario, HOST_SECRET_MOUNT_PATH, 10).to_dict()
    value[field] = replacement
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2EmptySecretMountIdentity.capture(
            value,
            observer=scenario.cleanup_observer,
            observed_boottime_ns=1_100_210,
        )


def test_empty_projection_and_unmount_receipt_reject_mount_reorder_and_equality() -> None:
    scenario = _scenario()
    mounts = _mounts(scenario)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2EmptySecretMountProjection.from_mounts(
            root=scenario.root,
            mounts=(mounts[1], mounts[0], mounts[2]),
        )
    projection = LifecycleV2EmptySecretMountProjection.from_mounts(
        root=scenario.root, mounts=mounts
    )
    with pytest.raises(TypeError):
        LifecycleV2SecretMountUnmountReceipt.completed(
            root=scenario.root,
            projection=projection,
            completed_boottime_ns=(
                1,
                2,
                scenario.root.operation_deadline_boottime_ns,
            ),
        )


def test_native_owner_set_rejects_unknown_duplicate_reordered_and_wrong_process() -> None:
    scenario = _scenario()
    valid = [
        {
            "owner_kind": "docker_effect_client",
            "owner_process_epoch_sha256": scenario.root.host_process_epoch_sha256,
            "owner_nonce_sha256": _digest("docker-owner"),
        },
        {
            "owner_kind": "transport_channel",
            "owner_process_epoch_sha256": scenario.root.host_process_epoch_sha256,
            "owner_nonce_sha256": _digest("transport-owner"),
        },
    ]
    for changed in (
        [dict(valid[0], owner_kind="repository_owner")],
        [valid[1], valid[0]],
        [valid[0], dict(valid[0])],
        [dict(valid[0], owner_process_epoch_sha256=scenario.root.supervisor_process_epoch_sha256)],
    ):
        with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
            LifecycleV2NativeOwnerSet.capture(
                root=scenario.root,
                observer=scenario.cleanup_observer,
                owners=changed,
                observed_boottime_ns=1_100_220,
            )


def test_reauthentication_binding_is_sealed_distinct_and_strictly_post_teardown() -> None:
    scenario = _scenario()
    lineage = _through_eighteen(scenario)
    transcript = _prefix_transcript(scenario, lineage)
    lineage = lineage.retain_post_teardown_reauthentication_intent(
        prefix_transcript=transcript,
        provider_identity_sha256=_digest("provider"),
        call_deadline_boottime_ns=POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS,
        recorded_at_utc=UTC_TEXT,
    )
    intent = cast(LifecycleV2ReauthenticationIntent, lineage.semantic_at(19))
    with pytest.raises(TypeError):
        LifecycleV2AuthenticatedReauthenticationBinding(issuer_identity_sha256=_digest("forged"))
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        _mint_fake_lifecycle_v2_reauthentication_binding({}, root=scenario.root, intent=intent)
    pre = cast(
        LifecycleV2AuthenticatedReauthenticationBinding,
        lineage.pre_effect_binding,
    )
    pre_fields = pre.to_dict()
    value = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-post-teardown-reauthentication-binding-v2"
        ),
        "service": LIFECYCLE_V2_CLEANUP_SERVICE,
        "status": "post_teardown_reauthentication_bound",
        "environment": scenario.root.environment,
        "graceful_stop_operation_id": scenario.root.graceful_stop_operation_id,
        "lifecycle_root_sha256": scenario.root.sha256,
        "channel_id": scenario.root.channel_id,
        "boundary": "post_teardown",
        "intent_semantic_sha256": intent.sha256,
        "issuer_identity_sha256": pre_fields["issuer_identity_sha256"],
        "challenge_sha256": pre_fields["challenge_sha256"],
        "observation_semantic_sha256": _digest("post-observation"),
        "observed_head_sha256": intent.to_dict()["expected_head_sha256"],
        "provider_identity_sha256": intent.to_dict()["provider_identity_sha256"],
        "observation_started_boottime_ns": 1_100_000,
        "observation_completed_boottime_ns": 1_100_100,
    }
    binding = _mint_fake_lifecycle_v2_reauthentication_binding(
        value,
        root=scenario.root,
        intent=intent,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_post_teardown_reauthentication_binding(
            binding=binding, recorded_at_utc=UTC_TEXT
        )


def test_reauthentication_intents_reject_non_exact_120_second_deadlines() -> None:
    scenario = _scenario()
    plan = _transport_plan(scenario)
    lineage = scenario.lineage.retain_transport_cleanup_commitment(
        plan=plan, recorded_at_utc=UTC_TEXT
    )
    lineage = lineage.confirm_transport_channel_quiesced(
        quiescence=_transport_quiescence(scenario, plan, lineage.last_record),
        recorded_at_utc=UTC_TEXT,
    )
    for deadline in (
        PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS - 1,
        PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS + 1,
        scenario.root.operation_deadline_boottime_ns,
    ):
        with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
            lineage.retain_pre_effect_reauthentication_intent(
                provider_identity_sha256=_digest("provider"),
                call_deadline_boottime_ns=deadline,
                recorded_at_utc=UTC_TEXT,
            )


def test_terminal_cleanup_rejects_cross_root_absence_and_stale_final_observation() -> None:
    scenario = _scenario()
    lineage = _through_eighteen(scenario)
    transcript = _prefix_transcript(scenario, lineage)
    lineage = lineage.retain_post_teardown_reauthentication_intent(
        prefix_transcript=transcript,
        provider_identity_sha256=_digest("provider"),
        call_deadline_boottime_ns=POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS,
        recorded_at_utc=UTC_TEXT,
    )
    intent = cast(LifecycleV2ReauthenticationIntent, lineage.semantic_at(19))
    binding = _binding(
        scenario.root,
        intent,
        issuer="post-issuer",
        challenge="post-challenge",
        observation="post-observation",
        started=1_100_000,
        completed=1_100_100,
    )
    lineage = lineage.retain_post_teardown_reauthentication_binding(
        binding=binding, recorded_at_utc=UTC_TEXT
    )
    other_root = replace(
        scenario.root,
        graceful_stop_operation_id="523e4567-e89b-42d3-a456-426614174099",
    )
    other_observer = _build_injected_fake_lifecycle_v2_cleanup_observer(
        root=other_root,
        observer_nonce_sha256=_digest("other-cleanup-observer"),
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_terminal_cleanup_intent(
            observer=scenario.cleanup_observer,
            mounts=_mounts(scenario),
            recovery_secret_mount_absence=LifecycleV2PathAbsence.recovery_secret_mount(
                root=other_root,
                observer=other_observer,
                observed_boottime_ns=1_100_200,
            ),
            socket_path_absence=LifecycleV2PathAbsence.transport_socket(
                root=scenario.root,
                observer=scenario.cleanup_observer,
                observed_boottime_ns=1_100_201,
            ),
            credential_path_absence=LifecycleV2PathAbsence.credential_paths(
                root=scenario.root,
                observer=scenario.cleanup_observer,
                observed_boottime_ns=1_100_202,
            ),
            native_owner_set=_owners(scenario.root, scenario.cleanup_observer),
            cleanup_authorized_boottime_ns=1_100_250,
            recorded_at_utc=UTC_TEXT,
        )
    mounts = _mounts(scenario)
    owners = _owners(scenario.root, scenario.cleanup_observer)
    lineage = lineage.retain_terminal_cleanup_intent(
        observer=scenario.cleanup_observer,
        mounts=mounts,
        recovery_secret_mount_absence=LifecycleV2PathAbsence.recovery_secret_mount(
            root=scenario.root,
            observer=scenario.cleanup_observer,
            observed_boottime_ns=1_100_200,
        ),
        socket_path_absence=LifecycleV2PathAbsence.transport_socket(
            root=scenario.root,
            observer=scenario.cleanup_observer,
            observed_boottime_ns=1_100_201,
        ),
        credential_path_absence=LifecycleV2PathAbsence.credential_paths(
            root=scenario.root,
            observer=scenario.cleanup_observer,
            observed_boottime_ns=1_100_202,
        ),
        native_owner_set=owners,
        cleanup_authorized_boottime_ns=1_100_250,
        recorded_at_utc=UTC_TEXT,
    )
    authorization = lineage.terminal_cleanup_authorization
    assert authorization is not None
    empty = LifecycleV2EmptySecretMountProjection.from_mounts(root=scenario.root, mounts=mounts)
    unmount = LifecycleV2SecretMountUnmountReceipt.completed(
        root=scenario.root,
        projection=empty,
        authorization=authorization,
        completed_boottime_ns=(1_100_300, 1_100_400, 1_100_500),
    )
    owner_receipt = LifecycleV2NativeOwnerCleanupReceipt.completed(
        root=scenario.root,
        owners=owners,
        authorization=authorization,
        completed_boottime_ns=1_100_600,
    )
    final_recovery = LifecycleV2PathAbsence.recovery_secret_mount(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_700,
    )
    stale_socket = LifecycleV2PathAbsence.transport_socket(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_550,
    )
    final_credentials = LifecycleV2PathAbsence.credential_paths(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_701,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        lineage.retain_terminal_cleanup_confirmed(
            empty_mount_projection=empty,
            unmount_receipt=unmount,
            native_owner_cleanup_receipt=owner_receipt,
            recovery_secret_mount_absence=final_recovery,
            socket_absence=stale_socket,
            credential_path_absence=final_credentials,
            recorded_at_utc=UTC_TEXT,
        )


def test_mixed_v1_and_digest_only_values_are_rejected_at_typed_boundaries() -> None:
    scenario = _scenario()
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2NormalProgressLineage.from_retained_result(
            root=cast(Any, {"lifecycle_version": 1}),
            result_record=scenario.result_record,
            terminal_wire_evidence=scenario.terminal_wire,
            clean_stop_result=scenario.clean_stop_result,
        )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        scenario.lineage.retain_transport_cleanup_commitment(
            plan=cast(
                Any,
                {
                    "clean_stop_result_sha256": scenario.terminal_wire.to_dict()[
                        "clean_stop_result_sha256"
                    ]
                },
            ),
            recorded_at_utc=UTC_TEXT,
        )


def test_canonical_semantics_and_docker_results_reject_object_new_forgery() -> None:
    forged_mount = object.__new__(LifecycleV2EmptySecretMountIdentity)
    object.__setattr__(forged_mount, "fields", FrozenJsonObject.capture({}))
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        forged_mount.to_dict()

    forged_result = object.__new__(DockerMutationResultSemantic)
    object.__setattr__(forged_result, "fields", FrozenJsonObject.capture({}))
    object.__setattr__(forged_result, "digest_domain", "forged")
    with pytest.raises(TrustedTimeDockerEvidenceRejected, match="not sealed"):
        forged_result.to_dict()

    forged_wire = object.__new__(LifecycleV2TerminalWireEvidence)
    object.__setattr__(forged_wire, "fields", FrozenJsonObject.capture({}))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="not sealed"):
        forged_wire.to_dict()


def test_non_authority_facts_remain_closed() -> None:
    assert lifecycle_v2_semantics_non_authority_facts() == {
        "transport_opened": False,
        "docker_called": False,
        "signature_authenticated": False,
        "reauthentication_issuer_consumed": False,
        "artifact_published": False,
        "stop_authority_granted": False,
        "production_cleanup_observer_present": False,
        "raw_cleanup_assertion_authority_present": False,
        "production_caller_present": False,
    }


def test_runtime_registries_and_generic_materializer_are_not_module_reachable() -> None:
    assert not hasattr(lifecycle_module, "_LIFECYCLE_VALUE_SEALS")
    assert not hasattr(docker_semantics_module, "_DOCKER_RESULT_SEALS")
    assert not hasattr(terminal_semantics_module, "_TERMINAL_WIRE_EVIDENCE_SEALS")
    assert not hasattr(LifecycleV2NormalProgressLineage, "_materialize_validated_stage")
    assert not hasattr(lifecycle_module, "_TYPED_STAGE_CAPABILITY")
    assert not hasattr(lifecycle_module, "_LINEAGE_CAPABILITY")
    assert not hasattr(lifecycle_module, "_mint_terminal_cleanup_authorization")
    assert all(
        type(value).__name__ != "LifecycleV2RuntimeSealRegistry"
        for module in (
            lifecycle_module,
            docker_semantics_module,
            terminal_semantics_module,
        )
        for value in vars(module).values()
    )


@pytest.mark.parametrize("import_attack", ["module_object", "function"])
def test_reauthentication_realm_install_rejects_mutable_importer_spoof(
    monkeypatch: pytest.MonkeyPatch,
    import_attack: str,
) -> None:
    def forged_consumer(*_args: object, **_kwargs: object) -> object:
        return object()

    forged_consumer.__module__ = "packages.domain.trusted_time_graceful_stop_v2_reauthentication"
    forged_consumer.__name__ = (
        "_consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once"
    )
    installer = (
        lifecycle_module._install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer
    )
    fake_realm = SimpleNamespace(
        _consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once=(
            forged_consumer
        ),
        _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot=type(
            "_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot",
            (),
            {},
        ),
    )

    def fake_import(_name: str) -> SimpleNamespace:
        return fake_realm

    if import_attack == "module_object":
        monkeypatch.setattr(
            lifecycle_module,
            "importlib",
            SimpleNamespace(import_module=fake_import),
        )
    else:
        monkeypatch.setattr(lifecycle_module.importlib, "import_module", fake_import)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected, match="installation"):
        installer(forged_consumer)


def test_unregistered_reauthentication_primitive_builder_is_inert() -> None:
    lineage = _through_six(_scenario())
    intent = cast(LifecycleV2ReauthenticationIntent, lineage.semantic_at(5))
    sealed = cast(LifecycleV2AuthenticatedReauthenticationBinding, lineage.semantic_at(6))
    raw_builder = lifecycle_module._build_unregistered_authenticated_reauthentication_binding
    raw = raw_builder(sealed.to_dict(), root=lineage.root, intent=intent)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected, match="sealed"):
        raw.to_dict()


@pytest.mark.parametrize(
    "replacement",
    [
        {"effect_kind": "forged_clean_stop_result"},
        {"deadline_boottime_ns": 599_999_999_999},
    ],
)
def test_ordinal_two_requires_exact_effect_and_top_level_deadline(
    replacement: dict[str, object],
) -> None:
    scenario = _scenario()
    forged = replace(scenario.result_record, **replacement)
    plan = _transport_plan(scenario)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2NormalProgressLineage.from_retained_result(
            root=scenario.root,
            result_record=forged,
            terminal_wire_evidence=scenario.terminal_wire,
            clean_stop_result=scenario.clean_stop_result,
        )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2TransportCleanupPlan.from_retained_result(
            root=scenario.root,
            result_record=forged,
            terminal_wire_evidence=scenario.terminal_wire,
            clean_stop_result=scenario.clean_stop_result,
            host_identity=plan.host_identity,
        )


def test_post_teardown_transcript_rejects_digest_stage_predecessor_and_wire_substitution() -> None:
    for substitution in ("record_digest", "stage", "predecessor", "wire"):
        scenario = _scenario()
        lineage = _through_eighteen(scenario)
        transcript = _prefix_transcript(scenario, lineage)
        entries = list(transcript.entries)
        if substitution == "record_digest":
            entries[-1] = replace(
                entries[-1],
                record_artifact_sha256=_digest("forged-ordinal-eighteen"),
            )
        elif substitution == "stage":
            entries[-1] = replace(
                entries[-1],
                stage=LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
            )
        elif substitution == "predecessor":
            forged_predecessor = _digest("forged-ordinal-one")
            entries[1] = replace(
                entries[1],
                record_artifact_sha256=forged_predecessor,
            )
            entries[2] = replace(entries[2], predecessor_sha256=forged_predecessor)
        else:
            forged_wire_sha256 = _digest("forged-terminal-wire")
            forged_wire_file_name = (
                "trusted-time-post-enrollment-graceful-stop-v2-wire-result-"
                f"{forged_wire_sha256}.json"
            )
            assert entries[2].wire_artifact_path is not None
            entries[2] = replace(
                entries[2],
                wire_artifact_path=(
                    entries[2].wire_artifact_path.rsplit("/", maxsplit=1)[0]
                    + f"/{forged_wire_file_name}"
                ),
                wire_artifact_file_name=forged_wire_file_name,
                wire_artifact_sha256=forged_wire_sha256,
            )
        forged = replace(transcript, entries=tuple(entries))
        with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
            lineage.retain_post_teardown_reauthentication_intent(
                prefix_transcript=forged,
                provider_identity_sha256=_digest("provider"),
                call_deadline_boottime_ns=POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS,
                recorded_at_utc=UTC_TEXT,
            )


def test_lineage_and_success_evidence_reject_copy_pickle_mutation_and_reuse() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    copied = copy.copy(lineage)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        _ = copied.last_record
    try:
        restored = pickle.loads(pickle.dumps(lineage))
    except (pickle.PickleError, TypeError, AttributeError):
        restored = None
    if restored is not None:
        with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
            _ = restored.last_record

    snapshot = consume_exact_lifecycle_v2_confirmed_success_lineage(lineage)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        consume_exact_lifecycle_v2_confirmed_success_lineage(lineage)
    assert (
        consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot) is snapshot
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot)


def test_terminal_wire_and_docker_result_runtime_seals_reject_copy_and_mutation() -> None:
    scenario = _scenario()
    copied_wire = copy.copy(scenario.terminal_wire)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="not sealed"):
        copied_wire.to_dict()
    changed_wire = scenario.terminal_wire.fields.to_dict()
    changed_wire["call_completed_boottime_ns"] = 13
    object.__setattr__(
        scenario.terminal_wire,
        "fields",
        FrozenJsonObject.capture(changed_wire),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="not sealed"):
        scenario.terminal_wire.to_dict()

    lineage = _through_eighteen(_scenario())
    volume = cast(DockerVolumePreservationResult, lineage.semantic_at(18))
    copied_volume = copy.copy(volume)
    with pytest.raises(TrustedTimeDockerEvidenceRejected, match="not sealed"):
        copied_volume.to_dict()
    changed_volume = volume.fields.to_dict()
    changed_volume["proof_completed_boottime_ns"] = (
        cast(int, changed_volume["proof_completed_boottime_ns"]) + 1
    )
    object.__setattr__(volume, "fields", FrozenJsonObject.capture(changed_volume))
    with pytest.raises(TrustedTimeDockerEvidenceRejected, match="not sealed"):
        volume.to_dict()


def test_success_snapshot_rejects_post_issuance_cleanup_result_mutation() -> None:
    scenario = _scenario()
    snapshot = consume_exact_lifecycle_v2_confirmed_success_lineage(_complete_lineage(scenario))
    cleanup = snapshot.terminal_cleanup_result
    changed = cleanup.evidence.to_dict()
    changed["cleanup_completed_boottime_ns"] = (
        cast(int, changed["cleanup_completed_boottime_ns"]) + 1
    )
    object.__setattr__(cleanup, "evidence", FrozenJsonObject.capture(changed))
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot)


def test_retained_semantic_mutation_invalidates_the_whole_lineage() -> None:
    scenario = _scenario()
    lineage = _through_six(scenario)
    binding = cast(LifecycleV2AuthenticatedReauthenticationBinding, lineage.semantic_at(6))
    changed = binding.fields.to_dict()
    changed["challenge_sha256"] = _digest("mutated-retained-challenge")
    object.__setattr__(binding, "fields", FrozenJsonObject.capture(changed))
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        _ = lineage.last_record

    scenario = _scenario()
    lineage = _through_eighteen(scenario)
    docker_result = cast(DockerMutationResultSemantic, lineage.semantic_at(8))
    changed_result = docker_result.fields.to_dict()
    changed_result["call_completed_boottime_ns"] = (
        cast(int, changed_result["call_completed_boottime_ns"]) + 1
    )
    object.__setattr__(docker_result, "fields", FrozenJsonObject.capture(changed_result))
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        _ = lineage.last_record


def test_lineage_and_success_snapshot_are_thread_bound() -> None:
    scenario = _scenario()
    lineage = _through_six(scenario)
    failures: list[BaseException] = []

    def read_lineage() -> None:
        try:
            _ = lineage.last_record
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=read_lineage)
    worker.start()
    worker.join()
    assert len(failures) == 1
    assert type(failures[0]) is TrustedTimeLifecycleV2SemanticsRejected

    snapshot = consume_exact_lifecycle_v2_confirmed_success_lineage(_complete_lineage(_scenario()))
    failures.clear()

    def consume_snapshot() -> None:
        try:
            consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot)
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=consume_snapshot)
    worker.start()
    worker.join()
    assert len(failures) == 1
    assert type(failures[0]) is TrustedTimeLifecycleV2SemanticsRejected
    assert (
        consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot) is snapshot
    )


def test_lineage_and_success_snapshot_are_fork_bound() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    lineage = _through_six(_scenario())
    snapshot = consume_exact_lifecycle_v2_confirmed_success_lineage(_complete_lineage(_scenario()))
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        accepted: list[str] = []
        for operation in (
            lambda: lineage.last_record,
            lambda: consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot),
        ):
            try:
                operation()
            except TrustedTimeLifecycleV2SemanticsRejected:
                accepted.append("rejected")
            else:
                accepted.append("accepted")
        os.write(write_fd, ",".join(accepted).encode("ascii"))
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    outcome = os.read(read_fd, 64)
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)
    assert status == 0
    assert outcome == b"rejected,rejected"
    assert (
        consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot) is snapshot
    )


def test_literal_prefix_validators_reject_consumed_or_wrong_ordinal_lineages() -> None:
    scenario = _scenario()
    plan = _transport_plan(scenario)
    lineage = scenario.lineage.retain_transport_cleanup_commitment(
        plan=plan,
        recorded_at_utc=UTC_TEXT,
    )
    lineage = lineage.confirm_transport_channel_quiesced(
        quiescence=_transport_quiescence(scenario, plan, lineage.last_record),
        recorded_at_utc=UTC_TEXT,
    )
    lineage_five = lineage.retain_pre_effect_reauthentication_intent(
        provider_identity_sha256=_digest("provider"),
        call_deadline_boottime_ns=PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS,
        recorded_at_utc=UTC_TEXT,
    )
    assert require_exact_lifecycle_v2_normal_lineage_through_ordinal_5(lineage_five) is lineage_five
    binding = _binding(
        scenario.root,
        cast(LifecycleV2ReauthenticationIntent, lineage_five.semantic_at(5)),
        issuer="pre-issuer",
        challenge="pre-challenge",
        observation="pre-observation",
        started=40,
        completed=50,
    )
    lineage_six = lineage_five.retain_pre_effect_reauthentication_binding(
        binding=binding,
        recorded_at_utc=UTC_TEXT,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        require_exact_lifecycle_v2_normal_lineage_through_ordinal_5(lineage_five)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        require_exact_lifecycle_v2_normal_lineage_through_ordinal_19(lineage_six)


def test_fake_cleanup_observer_is_test_only_and_raw_assertions_are_unsealed() -> None:
    scenario = _scenario()
    production_root = replace(scenario.root, environment="production")
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        _build_injected_fake_lifecycle_v2_cleanup_observer(
            root=production_root,
            observer_nonce_sha256=_digest("production-fake"),
        )
    exact = LifecycleV2PathAbsence.transport_socket(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        observed_boottime_ns=1_100_201,
    )
    forged = object.__new__(LifecycleV2PathAbsence)
    object.__setattr__(forged, "fields", exact.fields)
    object.__setattr__(forged, "absence_kind", exact.absence_kind)
    object.__setattr__(forged, "authorization_intent_sha256", None)
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        forged.to_dict()


def test_cleanup_authorization_actions_are_one_shot_and_receipts_cannot_predate_intent() -> None:
    scenario = _scenario()
    lineage, mounts, owners = _through_twenty_one(scenario)
    authorization = lineage.terminal_cleanup_authorization
    assert authorization is not None
    projection = LifecycleV2EmptySecretMountProjection.from_mounts(
        root=scenario.root,
        mounts=mounts,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2SecretMountUnmountReceipt.completed(
            root=scenario.root,
            projection=projection,
            authorization=authorization,
            completed_boottime_ns=(
                authorization.authorized_boottime_ns,
                1_100_301,
                1_100_302,
            ),
        )
    LifecycleV2SecretMountUnmountReceipt.completed(
        root=scenario.root,
        projection=projection,
        authorization=authorization,
        completed_boottime_ns=(1_100_300, 1_100_301, 1_100_302),
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2SecretMountUnmountReceipt.completed(
            root=scenario.root,
            projection=projection,
            authorization=authorization,
            completed_boottime_ns=(1_100_303, 1_100_304, 1_100_305),
        )
    LifecycleV2NativeOwnerCleanupReceipt.completed(
        root=scenario.root,
        owners=owners,
        authorization=authorization,
        completed_boottime_ns=1_100_400,
    )
    LifecycleV2PathAbsence.transport_socket(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        authorization=authorization,
        observed_boottime_ns=1_100_500,
    )
    with pytest.raises(TrustedTimeLifecycleV2SemanticsRejected):
        LifecycleV2PathAbsence.transport_socket(
            root=scenario.root,
            observer=scenario.cleanup_observer,
            authorization=authorization,
            observed_boottime_ns=1_100_501,
        )
