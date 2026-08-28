from __future__ import annotations

import base64
import copy
import gc
import hashlib
import os
import threading
from contextlib import suppress
from dataclasses import dataclass
from types import FunctionType, MappingProxyType, MethodType, SimpleNamespace
from typing import Any, cast

import pytest

from packages.domain import trusted_time_graceful_stop_v2 as core_module
from packages.domain import trusted_time_graceful_stop_v2_recovery as recovery
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
    LIFECYCLE_V2_SERVICE,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    NORMAL_STAGE_BY_ORDINAL,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
    decode_lifecycle_v2_progress_record,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_progress_file_name,
    lifecycle_v2_wire_file_name,
)
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    LifecycleV2NormalProgressLineage,
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
    RECOVERY_CLASSIFICATION_REASON_CODES,
    LifecycleV2RecoveryClassificationEnvelope,
)
from packages.persistence import trusted_time_graceful_stop_v2 as persistence
from tests.unit.test_trusted_time_graceful_stop_v2_lifecycle_semantics import (
    _complete_lineage,
    _Scenario,
    _scenario,
)
from tests.unit.trusted_time_graceful_stop_v2_fakes import (
    FakeLifecycleV2ArtifactStore,
    FakeLifecycleV2RetainedWireVerifier,
    FakeLifecycleV2Transport,
    FakePublicationFault,
)

UTC_TEXT = "2026-08-27T12:00:00.000000Z"
ARTIFACT_DIRECTORY = "/injected/adr0121/trusted-time"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _assert_no_mutable_module_closure_state(*roots: object, module_name: str) -> None:
    pending = list(roots)
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        assert not isinstance(value, (dict, list, set))
        if isinstance(value, FunctionType) and value.__module__ == module_name:
            pending.extend(
                cell.cell_contents
                for cell in value.__closure__ or ()
            )
            pending.extend(value.__defaults__ or ())
            pending.extend((value.__kwdefaults__ or {}).values())
        elif isinstance(value, MethodType):
            pending.extend((value.__func__, value.__self__))
        elif isinstance(value, (tuple, frozenset, MappingProxyType)):
            if isinstance(value, MappingProxyType):
                pending.extend(value.keys())
                pending.extend(value.values())
            else:
                pending.extend(value)


def _root(*, environment: str = "test") -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment=environment,
        graceful_stop_operation_id="523e4567-e89b-42d3-a456-426614174002",
        graceful_stop_target_sha256=_digest("target"),
        graceful_stop_decision_v1_sha256=_digest("decision"),
        graceful_stop_operator_attestation_envelope_sha256=_digest("attestation"),
        historical_decision_receipt_sha256=_digest("historical"),
        admission_sha256=_digest("admission"),
        topology_sha256=_digest("topology"),
        topology_lease_sha256=_digest("lease"),
        trusted_head_sha256=_digest("head"),
        stop_authority_sha256=_digest("stop-authority"),
        transport_authority_manifest_sha256=_digest("manifest"),
        transport_key_generation=1,
        host_transport_key_id="host-key-1",
        supervisor_transport_key_id="supervisor-key-1",
        boot_epoch_sha256=_digest("boot"),
        host_process_epoch_sha256=_digest("host-process"),
        supervisor_process_epoch_sha256=_digest("supervisor-process"),
        channel_id=_digest("channel"),
        supervisor_container_id=_digest("supervisor"),
        source_container_id=_digest("source"),
        project_network_id=_digest("network"),
        chrony_command_socket_volume_identity_sha256=_digest("command-volume"),
        chrony_state_volume_identity_sha256=_digest("state-volume"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request_intent(
    root: LifecycleV2Root,
    basis: LifecycleV2CleanStopRequestBasis,
) -> LifecycleV2ProgressRecord:
    return LifecycleV2ProgressRecord(
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


def _terminal_envelope(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
) -> UnverifiedLifecycleV2TransportEnvelope:
    payload = canonical_v2_json_bytes(
        {
            "contract_version": "phase6d-trusted-time-head-anchor-clean-stop-result-v2",
            "service": "trusted-time-head-anchor-clean-stop-v2",
            "status": "exact_operation_bound_new_record_clean_stop_correlated_unqualified",
        },
        maximum_bytes=180_224,
    )
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": "supervisor_to_host",
            "frame_type": "clean_stop_result",
            "payload_contract_version": ("phase6d-trusted-time-head-anchor-clean-stop-result-v2"),
            "key_generation": root.transport_key_generation,
            "signing_key_id": root.supervisor_transport_key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(root, intent),
            "message_counter": 1,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _terminal_record(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
    store: FakeLifecycleV2ArtifactStore,
) -> LifecycleV2ProgressRecord:
    file_name = lifecycle_v2_wire_file_name(envelope)
    publication = store.preview_publication_receipt(file_name, envelope.encoded)
    identity = store.identity
    receipt = {
        "contract_version": (
            "phase6d-post-enrollment-graceful-stop-wire-envelope-publication-receipt-v2"
        ),
        "service": LIFECYCLE_V2_SERVICE,
        "status": "wire_envelope_published",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "artifact_kind": "signed_result_envelope",
        "artifact_directory_path": identity.artifact_directory_path,
        "artifact_directory_device": identity.directory_device,
        "artifact_directory_inode": identity.directory_inode,
        "artifact_path": f"{identity.artifact_directory_path}/{file_name}",
        "file_name": file_name,
        "file_device": publication.final_device,
        "file_inode": publication.final_inode,
        "file_mode": publication.final_mode,
        "file_size": publication.final_size,
        "signed_envelope_sha256": envelope.sha256,
        "envelope_contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "frame_type": envelope.frame_type,
        "payload_contract_version": envelope.to_dict()["payload_contract_version"],
        "payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
        "signature_sha256": envelope.signature_sha256,
        "key_generation": root.transport_key_generation,
        "signing_key_id": root.supervisor_transport_key_id,
        "channel_id": root.channel_id,
        "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(root, intent),
        "message_counter": 1,
        "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
        "directory_fsync_completed": True,
        "stable_readback_completed": True,
        "publication_authorized_boottime_ns": root.admission_started_boottime_ns + 3,
    }
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=2,
        stage=LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        predecessor_sha256=intent.sha256,
        effect_kind="clean_stop_result",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "intent_sha256": intent.sha256,
                "responder_identity_sha256": root.supervisor_process_epoch_sha256,
                "disposition": "authenticated_result",
                "clean_stop_result_artifact_path": f"{ARTIFACT_DIRECTORY}/{file_name}",
                "clean_stop_result_artifact_name": file_name,
                "clean_stop_result_sha256": envelope.sha256,
                "envelope_contract_version": (LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION),
                "frame_type": "clean_stop_result",
                "payload_contract_version": (
                    "phase6d-trusted-time-head-anchor-clean-stop-result-v2"
                ),
                "clean_stop_result_payload_sha256": hashlib.sha256(envelope.payload).hexdigest(),
                "clean_stop_result_signature_sha256": envelope.signature_sha256,
                "terminal_projection_sha256": _digest("terminal-projection"),
                "key_generation": root.transport_key_generation,
                "signing_key_id": root.supervisor_transport_key_id,
                "channel_id": root.channel_id,
                "lifecycle_dispatch_prefix_sha256": (
                    lifecycle_v2_dispatch_prefix_sha256(root, intent)
                ),
                "message_counter": 1,
                "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
                "wire_publication_receipt": receipt,
                "wire_publication_receipt_sha256": _digest("wire-receipt"),
                "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
                "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )


def _fake_authenticated_terminal(
    root: LifecycleV2Root,
    basis: LifecycleV2CleanStopRequestBasis,
    intent: LifecycleV2ProgressRecord,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> Any:
    request = LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)
    request_envelope = UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            **envelope.to_dict(),
            "direction": "host_to_supervisor",
            "frame_type": "clean_stop_request",
            "payload_contract_version": request.to_dict()["contract_version"],
            "signing_key_id": root.host_transport_key_id,
            "message_counter": 2,
            "payload_sha256": hashlib.sha256(request.encoded).hexdigest(),
            "payload_base64": base64.b64encode(request.encoded).decode("ascii"),
        }
    )
    return FakeLifecycleV2Transport(root, envelope).exchange(request, request_envelope)


def _intent_evidence(root: LifecycleV2Root, ordinal: int) -> dict[str, object]:
    return {
        "target_identity_sha256": _digest(f"target-{ordinal}"),
        "arguments_sha256": _digest(f"arguments-{ordinal}"),
        "admission_sha256": root.admission_sha256,
        "channel_id": root.channel_id,
        "call_deadline_boottime_ns": root.operation_deadline_boottime_ns,
    }


def _result_evidence(root: LifecycleV2Root, ordinal: int) -> dict[str, object]:
    return {
        "intent_sha256": _digest(f"intent-{ordinal}"),
        "responder_identity_sha256": _digest(f"responder-{ordinal}"),
        "disposition": "confirmed",
        "result_semantic_sha256": _digest(f"result-{ordinal}"),
        "call_started_boottime_ns": root.admission_started_boottime_ns + ordinal,
        "call_completed_boottime_ns": root.admission_started_boottime_ns + ordinal + 1,
    }


def _raw_reauthentication_result_evidence(
    root: LifecycleV2Root,
    ordinal: int,
) -> dict[str, object]:
    boundary = "pre_effect" if ordinal == 6 else "post_teardown"
    started = root.admission_started_boottime_ns + ordinal
    completed = started + 1
    deadline = started + 120_000_000_000
    current_anchor_sha256 = _digest(f"current-anchor-{ordinal}")
    issuer_binding_sha256 = _digest(f"issuer-binding-{ordinal}")
    read_only_configuration_sha256 = _digest(f"read-only-configuration-{ordinal}")
    observation: dict[str, object] = {
        "contract_version": "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1",
        "status": "provider_terminal_observed_under_stable_sql_authenticated",
        "anchor_sequence": 3,
        "checkpoint_reason": "clean_stop",
        "confirmed_anchor_count": 3,
        "local_transition_count": 3,
        "confirmed_anchor_local_transition_ordinal": 3,
        "remote_object_count": 3,
        "predecessor_anchor_sha256": _digest(f"predecessor-anchor-{ordinal}"),
        "current_host_head_sha256": _digest(f"current-head-{ordinal}"),
        "current_anchor_sha256": current_anchor_sha256,
        "current_anchor_semantic_sha256": _digest(f"anchor-semantic-{ordinal}"),
        "anchor_intent_semantic_sha256": _digest(f"anchor-intent-{ordinal}"),
        "candidate_remote_readback_sha256": current_anchor_sha256,
        "receipt_semantic_sha256": _digest(f"receipt-semantic-{ordinal}"),
        "receipt_observed_at_utc": UTC_TEXT,
        "remote_observation_sha256": _digest(f"remote-observation-{ordinal}"),
        "anchor_authority_sha256": _digest(f"anchor-authority-{ordinal}"),
        "deployment_identity_sha256": _digest(f"deployment-{ordinal}"),
        "runtime_database_identity_sha256": _digest(f"database-{ordinal}"),
        "anchor_project_identity_sha256": _digest(f"project-{ordinal}"),
        "source_authority_sha256": _digest(f"source-authority-{ordinal}"),
        "signing_public_key_sha256": _digest(f"signing-key-{ordinal}"),
        "host_identity_sha256": _digest(f"host-{ordinal}"),
        "principal_identity_sha256": _digest(f"principal-{ordinal}"),
        "bucket_identity_sha256": _digest(f"bucket-{ordinal}"),
        "observation_started_monotonic_ns": started,
        "observation_completed_monotonic_ns": completed,
        "deadline_monotonic_ns": deadline,
        "issuer_binding_sha256": issuer_binding_sha256,
        "read_only_configuration_sha256": read_only_configuration_sha256,
    }
    observation["semantic_sha256"] = hashlib.sha256(
        canonical_v2_json_bytes(observation, maximum_bytes=180_224)
    ).hexdigest()
    provider_projection = {
        name: observation[name]
        for name in (
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
    }
    provider_identity_sha256 = hashlib.sha256(
        b"AutoQuantTrader/trusted-time/graceful-stop/adr0109-provider-identity/v2\0"
        + canonical_v2_json_bytes(provider_projection, maximum_bytes=180_224)
    ).hexdigest()
    binding_evidence: dict[str, object] = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-"
            f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
        ),
        "service": LIFECYCLE_V2_SERVICE,
        "status": (
            "fresh_pre_effect_adr0109_observation_bound"
            if boundary == "pre_effect"
            else "distinct_post_teardown_adr0109_observation_bound"
        ),
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "lifecycle_root_sha256": root.sha256,
        "expected_checkpoint_reason": "clean_stop",
        "expected_clean_stop_head_sha256": current_anchor_sha256,
        "expected_clean_stop_terminal_result_semantic_sha256": _digest(
            f"terminal-result-{ordinal}"
        ),
        "adr0109_observation": observation,
        "adr0109_observation_sha256": hashlib.sha256(
            canonical_v2_json_bytes(observation, maximum_bytes=180_224)
        ).hexdigest(),
        "provider_identity_sha256": provider_identity_sha256,
        "observation_semantic_sha256": observation["semantic_sha256"],
        "adr0109_issuer_binding_sha256": issuer_binding_sha256,
        "adr0109_read_only_configuration_sha256": read_only_configuration_sha256,
        "issuer_challenge_sha256": _digest(f"issuer-challenge-{ordinal}"),
        "observation_started_monotonic_ns": started,
        "observation_completed_monotonic_ns": completed,
        "observation_deadline_monotonic_ns": deadline,
    }
    if boundary == "pre_effect":
        binding_evidence.update(
            {
                "clean_stop_request_sha256": _digest("clean-stop-request"),
                "clean_stop_result_sha256": _digest("clean-stop-result"),
                "channel_id": root.channel_id,
                "topology_sha256": root.topology_sha256,
                "topology_lease_sha256": root.topology_lease_sha256,
                "transport_quiescence_record_sha256": _digest("transport-quiescence"),
                "pre_effect_intent_sha256": _digest("pre-effect-intent"),
            }
        )
    else:
        binding_evidence.update(
            {
                "published_prefix_through_ordinal_18_sha256": _digest("prefix-18"),
                "pre_effect_binding_sha256": _digest("pre-effect-binding"),
                "supervisor_stop_result_sha256": _digest("supervisor-stop-result"),
                "source_stop_result_sha256": _digest("source-stop-result"),
                "supervisor_remove_result_sha256": _digest("supervisor-remove-result"),
                "source_remove_result_sha256": _digest("source-remove-result"),
                "project_network_remove_result_sha256": _digest("network-remove-result"),
                "volume_proof_sha256": _digest("volume-proof"),
                "post_teardown_intent_sha256": _digest("post-teardown-intent"),
            }
        )
    binding_semantic_sha256 = _digest(f"binding-{ordinal}")
    return {
        "intent_sha256": _digest(f"intent-{ordinal}"),
        "responder_identity_sha256": issuer_binding_sha256,
        "disposition": f"{boundary}_reauthentication_bound",
        "result_semantic_sha256": binding_semantic_sha256,
        "call_started_boottime_ns": started,
        "call_completed_boottime_ns": completed,
        "observation_semantic_sha256": observation["semantic_sha256"],
        "binding_semantic_sha256": binding_semantic_sha256,
        "observed_head_sha256": current_anchor_sha256,
        "provider_identity_sha256": provider_identity_sha256,
        "binding_evidence": binding_evidence,
    }


def _stage_evidence(
    root: LifecycleV2Root,
    stage: LifecycleV2Stage,
    ordinal: int,
) -> dict[str, object]:
    if stage is LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED:
        return {
            "clean_stop_result_sha256": _digest("wire"),
            "supervisor_cleanup_commitment_sha256": _digest("supervisor-cleanup"),
            "channel_id": root.channel_id,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "host_socket_identity_sha256": _digest("host-socket"),
            "host_peer_credential_sha256": _digest("peer"),
            "host_raw_key_path": "/run/autoquant/host.raw",
            "host_raw_key_device": 1,
            "host_raw_key_inode": 2,
            "host_challenge_sha256": _digest("challenge"),
            "host_process_nonce_sha256": _digest("nonce"),
            "cleanup_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
    if stage is LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED:
        return {
            "cleanup_commitment_record_sha256": _digest("cleanup-record"),
            "supervisor_cleanup_commitment_sha256": _digest("supervisor-cleanup"),
            "host_native_cleanup_receipt_sha256": _digest("native-cleanup"),
            "supervisor_quiescence_observation_sha256": _digest("quiescence"),
            "channel_eof_observed": True,
            "listener_fd_absent": True,
            "accepted_fd_absent": True,
            "socket_path_absent": True,
            "host_signer_zeroized": True,
            "host_challenge_zeroized": True,
            "host_process_nonce_zeroized": True,
            "credential_paths_absent": True,
            "cleanup_started_boottime_ns": root.admission_started_boottime_ns + 3,
            "cleanup_completed_boottime_ns": root.admission_started_boottime_ns + 4,
        }
    if stage in {
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
        LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
    }:
        return _intent_evidence(root, ordinal)
    if stage in {
        LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
        LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
    }:
        return _raw_reauthentication_result_evidence(root, ordinal)
    if stage in {
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
    }:
        return {
            **_intent_evidence(root, ordinal),
            "docker_request_semantic_sha256": _digest(f"docker-{ordinal}"),
            "docker_post_inspect_request_semantic_sha256": _digest(f"inspect-{ordinal}"),
        }
    if stage in {
        LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
        LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
        LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
    }:
        return {
            **_result_evidence(root, ordinal),
            "docker_request_semantic_sha256": _digest(f"docker-{ordinal - 1}"),
            "docker_post_inspect_request_semantic_sha256": _digest(f"inspect-{ordinal - 1}"),
            "result_semantic": {"outcome": "confirmed"},
            "docker_method_trace_entry_sha256_list": [
                _digest(f"trace-{ordinal}-1"),
                _digest(f"trace-{ordinal}-2"),
            ],
        }
    if stage is LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED:
        return {
            **_intent_evidence(root, ordinal),
            "docker_request_semantic_sha256_list": [
                _digest("command-request"),
                _digest("state-request"),
            ],
        }
    if stage is LifecycleV2Stage.NAMED_VOLUMES_PRESERVED:
        return {
            **_result_evidence(root, ordinal),
            "command_socket_volume_identity_sha256": (
                root.chrony_command_socket_volume_identity_sha256
            ),
            "state_volume_identity_sha256": (root.chrony_state_volume_identity_sha256),
            "docker_api_trace_sha256": _digest("docker-trace"),
            "volume_delete_call_count": 0,
            "docker_request_semantic_sha256_list": [
                _digest("command-request"),
                _digest("state-request"),
            ],
            "result_semantic": {"outcome": "volumes_preserved"},
            "docker_method_trace_entry_sha256_list": [
                _digest("volume-trace-1"),
                _digest("volume-trace-2"),
            ],
        }
    if stage is LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED:
        return {
            "transport_quiescence_record_sha256": _digest("quiescence-record"),
            "supervisor_remove_result_sha256": _digest("supervisor-remove"),
            "transport_mount_identity_sha256": _digest("transport-mount"),
            "host_secret_mount_identity_sha256": _digest("host-mount"),
            "supervisor_secret_mount_identity_sha256": _digest("supervisor-mount"),
            "recovery_secret_mount_absence_sha256": _digest("recovery-absent"),
            "socket_path_absence_sha256": _digest("socket-absent"),
            "credential_path_absence_sha256": _digest("credentials-absent"),
            "native_owner_set_sha256": _digest("native-owners"),
            "cleanup_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
    if stage is LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED:
        return {
            "cleanup_intent_sha256": _digest("cleanup-intent"),
            "transport_quiescence_record_sha256": _digest("quiescence-record"),
            "supervisor_remove_result_sha256": _digest("supervisor-remove"),
            "socket_absence_sha256": _digest("socket-absent"),
            "credential_path_absence_sha256": _digest("credentials-absent"),
            "empty_mount_projection_sha256": _digest("empty-mounts"),
            "unmount_receipt_sha256": _digest("unmount"),
            "native_owner_cleanup_receipt_sha256": _digest("native-cleanup"),
            "all_private_material_unreachable": True,
            "cleanup_completed_boottime_ns": root.admission_started_boottime_ns + 22,
        }
    raise AssertionError(stage)


def _record(
    root: LifecycleV2Root,
    predecessor: LifecycleV2ProgressRecord,
    ordinal: int,
) -> LifecycleV2ProgressRecord:
    stage = NORMAL_STAGE_BY_ORDINAL[ordinal]
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=ordinal,
        stage=stage,
        predecessor_sha256=predecessor.sha256,
        effect_kind=f"stage_{ordinal}",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(_stage_evidence(root, stage, ordinal)),
        recorded_at_utc=UTC_TEXT,
    )


class _SealedLineageArtifactStore(FakeLifecycleV2ArtifactStore):
    def __init__(
        self,
        *,
        initial: dict[str, bytes] | None = None,
        fault: FakePublicationFault | None = None,
    ) -> None:
        super().__init__(
            initial=initial,
            fault=fault,
            identity=persistence.LifecycleV2ArtifactStoreIdentity(
                artifact_directory_path=ARTIFACT_DIRECTORY,
                directory_device=1,
                directory_inode=2,
                owner_uid=501,
                owner_gid=20,
                directory_mode=0o700,
            ),
        )

    @staticmethod
    def file_inode(file_name: str) -> int:
        if "-wire-result-" in file_name:
            return 3
        return FakeLifecycleV2ArtifactStore.file_inode(file_name)


def _repository(
    store: FakeLifecycleV2ArtifactStore,
) -> Any:
    return persistence._open_injected_lifecycle_v2_repository(
        store,
        artifact_directory_path=ARTIFACT_DIRECTORY,
        retained_wire_verifier=FakeLifecycleV2RetainedWireVerifier(),
    )


def test_repository_exposes_no_generic_progress_retention_primitive() -> None:
    repository = _repository(FakeLifecycleV2ArtifactStore())

    assert not hasattr(repository, "_retain_progress")
    assert not hasattr(persistence, "_retain_progress")
    assert not hasattr(persistence, "_build_named_lifecycle_v2_retention_endpoints")
    assert "retain_record" not in vars(persistence)


def test_fake_terminal_wire_path_rejects_production_root_live_and_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _SealedLineageArtifactStore()
    repository = _repository(store)
    production_root = _root(environment="production")
    repository.reserve_root(production_root)
    forged_authenticated = object()
    terminal_record = _scenario().result_record
    monkeypatch.setattr(
        persistence,
        "_require_fake_authenticated_lifecycle_v2_transport_envelope",
        lambda value, **_kwargs: value,
        raising=False,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="confined to test roots",
    ):
        repository.retain_authenticated_terminal_wire(
            terminal_record,
            forged_authenticated,
        )

    initial = {
        name: store.read_stable(name).encoded for name in store.inventory().names
    }
    reopened_store = _SealedLineageArtifactStore(initial=initial)
    reopened = _repository(reopened_store)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="confined to test roots",
    ):
        reopened.retain_authenticated_terminal_wire(
            terminal_record,
            forged_authenticated,
        )
    assert all("wire-" not in name for name in reopened_store.inventory().names)


def test_unbound_terminal_wire_receipt_is_rejected_live_and_on_restart() -> None:
    scenario = _scenario()
    envelope = _lineage_terminal_envelope(scenario)
    basis = LifecycleV2CleanStopRequestBasis.from_root(scenario.root)
    evidence = scenario.result_record.evidence.to_dict()
    receipt = dict(cast(dict[str, object], evidence["wire_publication_receipt"]))
    receipt["attacker_controlled"] = {"semantic": "unbound"}
    evidence["wire_publication_receipt"] = receipt
    evidence["wire_publication_receipt_sha256"] = "f" * 64
    changed = _unsafe_record_with_evidence(scenario.result_record, evidence)
    live_store = _SealedLineageArtifactStore()
    repository = _repository(live_store)
    repository.reserve_root(scenario.root)
    repository.retain_request_intent(scenario.request_intent, basis)

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="canonically valid",
    ):
        repository.retain_authenticated_terminal_wire(
            changed,
            _fake_authenticated_terminal(
                scenario.root,
                basis,
                scenario.request_intent,
                envelope,
            ),
        )

    valid_store = _SealedLineageArtifactStore()
    _, _, lineage = _complete_sealed_success_prefix(valid_store)
    initial = _replace_record_artifact(
        valid_store,
        lineage.record_at(2),
        changed,
    )
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(_SealedLineageArtifactStore(initial=initial))


@pytest.mark.parametrize("ordinal", [8, 18])
def test_unbound_docker_or_volume_semantic_is_rejected_live_and_on_restart(
    ordinal: int,
) -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    original = lineage.record_at(ordinal)
    evidence = original.evidence.to_dict()
    evidence["result_semantic"] = {"attacker_controlled": True}
    evidence["result_semantic_sha256"] = "f" * 64
    changed = _unsafe_record_with_evidence(original, evidence)
    live_store = _SealedLineageArtifactStore()
    repository = _retain_sealed_success_prefix(
        live_store,
        scenario,
        lineage,
        through_ordinal=ordinal - 1,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="canonically valid",
    ):
        repository.retain_effect_result(changed)

    valid_scenario = _scenario()
    valid_lineage = _complete_lineage(valid_scenario)
    valid_original = valid_lineage.record_at(ordinal)
    valid_evidence = valid_original.evidence.to_dict()
    valid_evidence["result_semantic"] = {"attacker_controlled": True}
    valid_evidence["result_semantic_sha256"] = "f" * 64
    valid_changed = _unsafe_record_with_evidence(valid_original, valid_evidence)
    valid_store = _SealedLineageArtifactStore()
    _retain_sealed_success_prefix(valid_store, valid_scenario, valid_lineage)
    initial = _replace_record_artifact(valid_store, valid_original, valid_changed)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(_SealedLineageArtifactStore(initial=initial))


def test_unbound_terminal_cleanup_intent_is_rejected_live_and_on_restart() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    original = lineage.record_at(21)
    value = original.to_dict()
    evidence = cast(dict[str, object], value["evidence"])
    evidence["transport_quiescence_record_sha256"] = "f" * 64
    evidence["supervisor_remove_result_sha256"] = "e" * 64
    changed = decode_lifecycle_v2_progress_record(
        canonical_v2_json_bytes(value, maximum_bytes=256 * 1_024)
    )
    repository = _retain_sealed_success_prefix(
        _SealedLineageArtifactStore(),
        scenario,
        lineage,
        through_ordinal=20,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="terminal cleanup crossed",
    ):
        repository.retain_terminal_cleanup_intent(changed)

    valid_scenario = _scenario()
    valid_lineage = _complete_lineage(valid_scenario)
    valid_original = valid_lineage.record_at(21)
    valid_value = valid_original.to_dict()
    valid_evidence = cast(dict[str, object], valid_value["evidence"])
    valid_evidence["transport_quiescence_record_sha256"] = "f" * 64
    valid_evidence["supervisor_remove_result_sha256"] = "e" * 64
    valid_changed = decode_lifecycle_v2_progress_record(
        canonical_v2_json_bytes(valid_value, maximum_bytes=256 * 1_024)
    )
    valid_store = _SealedLineageArtifactStore()
    _retain_sealed_success_prefix(valid_store, valid_scenario, valid_lineage)
    initial = _replace_record_artifact(valid_store, valid_original, valid_changed)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(_SealedLineageArtifactStore(initial=initial))


def test_unbound_terminal_cleanup_result_is_rejected_live_and_on_restart() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    original = lineage.record_at(22)
    evidence = original.evidence.to_dict()
    evidence["cleanup_intent_sha256"] = "e" * 64
    evidence["empty_mount_projection_sha256"] = "d" * 64
    evidence["native_owner_cleanup_receipt_sha256"] = "c" * 64
    changed = _unsafe_record_with_evidence(original, evidence)
    repository = _retain_sealed_success_prefix(
        _SealedLineageArtifactStore(),
        scenario,
        lineage,
        through_ordinal=21,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="canonically valid",
    ):
        repository.retain_terminal_cleanup_result(changed)

    valid_scenario = _scenario()
    valid_lineage = _complete_lineage(valid_scenario)
    valid_original = valid_lineage.record_at(22)
    valid_evidence = valid_original.evidence.to_dict()
    valid_evidence["cleanup_intent_sha256"] = "e" * 64
    valid_evidence["empty_mount_projection_sha256"] = "d" * 64
    valid_evidence["native_owner_cleanup_receipt_sha256"] = "c" * 64
    valid_changed = _unsafe_record_with_evidence(valid_original, valid_evidence)
    valid_store = _SealedLineageArtifactStore()
    _retain_sealed_success_prefix(valid_store, valid_scenario, valid_lineage)
    initial = _replace_record_artifact(valid_store, valid_original, valid_changed)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(_SealedLineageArtifactStore(initial=initial))


def _lineage_terminal_envelope(scenario: _Scenario) -> UnverifiedLifecycleV2TransportEnvelope:
    root = scenario.root
    request = LifecycleV2CleanStopRequest.from_prefix(
        root,
        LifecycleV2CleanStopRequestBasis.from_root(root),
        scenario.request_intent,
    )
    result = scenario.clean_stop_result
    envelope = UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": "supervisor_to_host",
            "frame_type": "clean_stop_result",
            "payload_contract_version": result.to_dict()["contract_version"],
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
    assert envelope.sha256 == scenario.terminal_wire.to_dict()["clean_stop_result_sha256"]
    return envelope


def _retain_sealed_success_prefix(
    store: FakeLifecycleV2ArtifactStore,
    scenario: _Scenario,
    lineage: LifecycleV2NormalProgressLineage,
    *,
    clone_ordinal: int | None = None,
    clone_all: bool = False,
    through_ordinal: int = 22,
) -> Any:
    root = scenario.root
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(scenario.request_intent, basis)
    envelope = _lineage_terminal_envelope(scenario)
    terminal_record = (
        decode_lifecycle_v2_progress_record(scenario.result_record.encoded)
        if clone_all or clone_ordinal == 2
        else scenario.result_record
    )
    repository.retain_authenticated_terminal_wire(
        terminal_record,
        _fake_authenticated_terminal(root, basis, scenario.request_intent, envelope),
    )
    for sealed_record in lineage.records[1:]:
        if sealed_record.ordinal > through_ordinal:
            break
        record = (
            decode_lifecycle_v2_progress_record(sealed_record.encoded)
            if clone_all or clone_ordinal == sealed_record.ordinal
            else sealed_record
        )
        if record.ordinal == 3:
            repository.retain_transport_cleanup_commitment(record)
        elif record.ordinal == 4:
            repository.retain_transport_quiescence(record)
        elif record.ordinal in {5, 19}:
            repository.retain_reauthentication_intent(record)
        elif record.ordinal in {6, 20}:
            repository.retain_reauthentication_result(record)
        elif record.ordinal in {7, 9, 11, 13, 15, 17}:
            repository.retain_effect_intent(record)
        elif record.ordinal in {8, 10, 12, 14, 16, 18}:
            repository.retain_effect_result(record)
        elif record.ordinal == 21:
            repository.retain_terminal_cleanup_intent(record)
        else:
            repository.retain_terminal_cleanup_result(record)
    repository.publish_transcript()
    return repository


def _unsafe_record_with_evidence(
    record: LifecycleV2ProgressRecord,
    evidence: dict[str, object],
) -> LifecycleV2ProgressRecord:
    forged = object.__new__(LifecycleV2ProgressRecord)
    for name in (
        "graceful_stop_operation_id",
        "root_sha256",
        "ordinal",
        "stage",
        "predecessor_sha256",
        "effect_kind",
        "deadline_boottime_ns",
        "recorded_at_utc",
    ):
        object.__setattr__(forged, name, getattr(record, name))
    object.__setattr__(forged, "evidence", FrozenJsonObject.capture(evidence))
    return forged


def _replace_record_artifact(
    store: FakeLifecycleV2ArtifactStore,
    original: LifecycleV2ProgressRecord,
    changed: LifecycleV2ProgressRecord,
) -> dict[str, bytes]:
    initial = {
        name: store.read_stable(name).encoded for name in store.inventory().names
    }
    del initial[lifecycle_v2_progress_file_name(original)]
    initial[lifecycle_v2_progress_file_name(changed)] = changed.encoded
    return initial


def _complete_sealed_success_prefix(
    store: FakeLifecycleV2ArtifactStore,
) -> tuple[Any, LifecycleV2Root, LifecycleV2NormalProgressLineage]:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    repository = _retain_sealed_success_prefix(store, scenario, lineage)
    root = scenario.root
    return repository, root, lineage


def _complete_raw_success_prefix(
    store: FakeLifecycleV2ArtifactStore,
) -> tuple[Any, LifecycleV2Root]:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    repository = _retain_sealed_success_prefix(
        store,
        scenario,
        lineage,
        clone_all=True,
    )
    return repository, scenario.root


def _recovery_envelope(
    root: LifecycleV2Root,
    transcript: Any,
    *,
    reason: str = "call_or_result_ambiguous",
    nonce: bytes = bytes(range(32)),
) -> LifecycleV2RecoveryClassificationEnvelope:
    return LifecycleV2RecoveryClassificationEnvelope.capture(
        {
            "contract_version": RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "recovery_classification_requested",
            "environment": root.environment,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            "transcript_sha256": transcript.sha256,
            "last_ordinal": transcript.entries[-1].ordinal,
            "last_stage": transcript.entries[-1].stage.value,
            "reason_code": reason,
            "transport_authority_manifest_sha256": (root.transport_authority_manifest_sha256),
            "key_generation": root.transport_key_generation,
            "recovery_key_id": "recovery-key-1",
            "operator_nonce_base64": base64.b64encode(nonce).decode("ascii"),
            "issued_at_utc": UTC_TEXT,
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _fake_recovery_intent(
    root: LifecycleV2Root,
    transcript: Any,
    *,
    reason: str = "call_or_result_ambiguous",
) -> recovery.LifecycleV2AuthenticatedRecoveryIntent:
    return recovery._build_injected_fake_lifecycle_v2_recovery_intent(
        envelope=_recovery_envelope(root, transcript, reason=reason),
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )


class _Clock:
    def __init__(self, samples: list[object], events: list[str] | None = None) -> None:
        self.samples = list(samples)
        self.events = events

    def sample_boottime_ns(self) -> int:
        if self.events is not None:
            self.events.append("clock")
        if not self.samples:
            raise RuntimeError("no sample")
        value = self.samples.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]


_DISPOSITION_CAPABILITY = object()


@dataclass(frozen=True, slots=True)
class _Disposition:
    root_sha256: str
    transcript_sha256: str
    outcome_sha256: str
    candidate_handle_disposed: bool
    transcript_handle_disposed: bool
    transient_descriptor_count: int
    registry_entry_count: int
    capability: object


class _Disposer:
    def __init__(
        self,
        *,
        events: list[str] | None = None,
        descriptor_count: int = 0,
        registry_count: int = 0,
    ) -> None:
        self.events = events
        self.descriptor_count = descriptor_count
        self.registry_count = registry_count

    def dispose_and_prove_empty(
        self,
        *,
        root: LifecycleV2Root,
        transcript: Any,
        outcome: Any,
        artifact_store_identity: Any,
    ) -> object:
        if self.events is not None:
            self.events.append("dispose")
        assert artifact_store_identity.artifact_directory_path == ARTIFACT_DIRECTORY
        return _Disposition(
            root_sha256=root.sha256,
            transcript_sha256=transcript.sha256,
            outcome_sha256=outcome.sha256,
            candidate_handle_disposed=True,
            transcript_handle_disposed=True,
            transient_descriptor_count=self.descriptor_count,
            registry_entry_count=self.registry_count,
            capability=_DISPOSITION_CAPABILITY,
        )

    def require_exact_disposed_and_empty(self, result: object) -> _Disposition:
        if type(result) is not _Disposition or result.capability is not _DISPOSITION_CAPABILITY:
            raise ValueError("disposition is not sealed")
        return result


class _TraceStore(_SealedLineageArtifactStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.trace = events

    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> persistence.LifecycleV2ArtifactPublicationReceipt:
        if "outcome-" in final_name and not final_name.startswith("."):
            self.trace.append("candidate_publish")
        elif final_name == LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME:
            self.trace.append("marker_publish")
        return super().publish_immutable(
            staging_name=staging_name,
            final_name=final_name,
            encoded=encoded,
        )

    def read_stable(self, file_name: str) -> persistence.LifecycleV2ArtifactReadback:
        if "outcome-" in file_name and not file_name.startswith("."):
            self.trace.append("candidate_readback")
        return super().read_stable(file_name)


def _recovery_prefix(
    store: FakeLifecycleV2ArtifactStore,
    *,
    reason: str = "call_or_result_ambiguous",
) -> tuple[Any, LifecycleV2Root]:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    intent = _request_intent(root, basis)
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    classified = repository.publish_transcript()
    authenticated_intent = _fake_recovery_intent(root, classified, reason=reason)
    retained = repository.retain_recovery_classification_intent(authenticated_intent)
    assert retained == authenticated_intent.record
    final = repository.publish_transcript()
    assert final.entries[-1].stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
    assert final.sha256 != classified.sha256
    return repository, root


def _classified_recovery_inputs(
    *,
    environment: str = "test",
) -> tuple[LifecycleV2Root, Any]:
    root = _root(environment=environment)
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository = _repository(FakeLifecycleV2ArtifactStore())
    repository.reserve_root(root)
    repository.retain_request_intent(_request_intent(root, basis), basis)
    return root, repository.publish_transcript()


def test_fake_recovery_issuance_is_registry_owned_and_test_root_only() -> None:
    assert not hasattr(recovery, "_FAKE_RECOVERY_INTENT_CAPABILITY")
    assert not hasattr(recovery, "_mint_fake_authenticated_lifecycle_v2_recovery_intent")
    assert not hasattr(recovery, "_lifecycle_v2_recovery_intent_issuance_registry")
    root, transcript = _classified_recovery_inputs(environment="production")

    with pytest.raises(
        TrustedTimeGracefulStopV2Rejected,
        match="exact test root",
    ):
        _fake_recovery_intent(root, transcript)


def test_replacing_fake_recovery_builder_cannot_register_a_forged_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = recovery._build_injected_fake_lifecycle_v2_recovery_intent
    root, transcript = _classified_recovery_inputs()
    forged = object.__new__(recovery.LifecycleV2AuthenticatedRecoveryIntent)
    monkeypatch.setattr(
        recovery,
        "_build_injected_fake_lifecycle_v2_recovery_intent",
        lambda **_kwargs: forged,
    )

    assert recovery._build_injected_fake_lifecycle_v2_recovery_intent() is forged
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="issuance snapshot"):
        recovery.require_authenticated_lifecycle_v2_recovery_intent(forged)
    monkeypatch.setattr(recovery, "_canonical_recovery_inputs", lambda **_kwargs: ())
    monkeypatch.setattr(recovery, "_build_recovery_intent_value", lambda **_kwargs: forged)
    monkeypatch.setattr(
        recovery,
        "_require_lifecycle_v2_recovery_intent_issuance",
        lambda *_args: forged,
    )

    issued = builder(
        envelope=_recovery_envelope(root, transcript),
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )
    assert issued is not forged
    assert recovery.require_authenticated_lifecycle_v2_recovery_intent(issued) is issued


def test_recovery_gc_introspection_cannot_forge_intent_consume_or_nonce_state() -> None:
    root, transcript = _classified_recovery_inputs()
    envelope = _recovery_envelope(root, transcript)
    authentic = _fake_recovery_intent(root, transcript)
    forged = copy.copy(authentic)

    fake_builder = recovery._build_injected_fake_lifecycle_v2_recovery_intent
    fake_closure = dict(
        zip(
            fake_builder.__code__.co_freevars,
            fake_builder.__closure__ or (),
            strict=True,
        )
    )
    register = fake_closure["register_issued_intent"].cell_contents
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="caller"):
        register(
            forged,
            envelope_encoded=envelope.encoded,
            root_encoded=root.encoded,
            classified_transcript_encoded=transcript.encoded,
            recorded_at_utc=UTC_TEXT,
            provenance="fake_test_recovery",
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="issuance snapshot"):
        recovery.require_authenticated_lifecycle_v2_recovery_intent(forged)

    require = recovery.require_authenticated_lifecycle_v2_recovery_intent
    require_closure = dict(
        zip(require.__code__.co_freevars, require.__closure__ or (), strict=True)
    )
    read_snapshot = require_closure["read_snapshot"].cell_contents
    read_closure = dict(
        zip(
            read_snapshot.__code__.co_freevars,
            read_snapshot.__closure__ or (),
            strict=True,
        )
    )
    snapshot_state = read_closure["snapshot_state"].cell_contents
    assert type(snapshot_state) is tuple
    assert not any(type(referent) is dict for referent in gc.get_referents(snapshot_state))
    snapshot = next(
        candidate for candidate in snapshot_state if candidate.value is authentic
    )
    snapshot.__init__(
        *snapshot._replace(provenance="production_authenticated_recovery")
    )
    assert snapshot.provenance == "fake_test_recovery"
    with pytest.raises(AttributeError):
        object.__setattr__(snapshot, "provenance", "production_authenticated_recovery")

    consume = recovery.consume_authenticated_lifecycle_v2_recovery_intent
    consume_closure = dict(
        zip(consume.__code__.co_freevars, consume.__closure__ or (), strict=True)
    )
    consume_snapshot = consume_closure["consume_snapshot"].cell_contents
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="caller"):
        consume_snapshot(authentic)
    assert recovery.consume_authenticated_lifecycle_v2_recovery_intent(authentic) is authentic
    consume_snapshot_closure = dict(
        zip(
            consume_snapshot.__code__.co_freevars,
            consume_snapshot.__closure__ or (),
            strict=True,
        )
    )
    consumed_state = consume_snapshot_closure["consumed_state"].cell_contents
    assert type(consumed_state) is frozenset
    assert id(authentic) in consumed_state
    assert not any(
        type(referent) in {dict, list, set, bytearray}
        for referent in gc.get_referents(consumed_state)
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already consumed"):
        recovery.consume_authenticated_lifecycle_v2_recovery_intent(authentic)

    derive = recovery._derive_authenticated_lifecycle_v2_recovery_intent
    derive_closure = dict(
        zip(derive.__code__.co_freevars, derive.__closure__ or (), strict=True)
    )
    reserve_nonce = derive_closure["reserve_production_nonce"].cell_contents
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="caller"):
        reserve_nonce(root.sha256, envelope.operator_nonce_sha256)
    reserve_closure = dict(
        zip(
            reserve_nonce.__code__.co_freevars,
            reserve_nonce.__closure__ or (),
            strict=True,
        )
    )
    nonce_state = reserve_closure["nonce_state"].cell_contents
    assert type(nonce_state) is frozenset
    assert not any(
        type(referent) in {dict, list, set, bytearray}
        for referent in gc.get_referents(nonce_state)
    )

    _assert_no_mutable_module_closure_state(
        fake_builder,
        derive,
        require,
        recovery.consume_authenticated_lifecycle_v2_recovery_intent,
        module_name=recovery.__name__,
    )


def test_recovery_builder_defaults_cannot_substitute_authenticated_classification() -> None:
    store = FakeLifecycleV2ArtifactStore()
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(_request_intent(root, basis), basis)
    transcript = repository.publish_transcript()
    authenticated = _recovery_envelope(
        root,
        transcript,
        reason="deadline_expired",
    )
    substituted = _recovery_envelope(
        root,
        transcript,
        reason="lock_lost",
        nonce=b"Z" * 32,
    )

    fake_builder = recovery._build_injected_fake_lifecycle_v2_recovery_intent
    fake_closure = dict(
        zip(
            fake_builder.__code__.co_freevars,
            fake_builder.__closure__ or (),
            strict=True,
        )
    )
    build_intent = fake_closure["build_intent_value"].cell_contents
    build_closure = dict(
        zip(
            build_intent.__code__.co_freevars,
            build_intent.__closure__ or (),
            strict=True,
        )
    )
    original_build_intent = build_closure["original_build_intent_value"].cell_contents
    build_defaults = original_build_intent.__kwdefaults__
    assert build_defaults is not None
    record_builder = build_defaults["_record_builder"]
    record_defaults = record_builder.__kwdefaults__
    assert record_defaults is not None
    original_canonicalizer = record_defaults["_canonicalize"]

    def substitute_classification(
        *,
        envelope: LifecycleV2RecoveryClassificationEnvelope,
        root: LifecycleV2Root,
        classified_transcript: Any,
    ) -> tuple[LifecycleV2RecoveryClassificationEnvelope, LifecycleV2Root, Any]:
        del envelope
        return substituted, root, classified_transcript

    try:
        record_defaults["_canonicalize"] = substitute_classification
        intent = recovery._build_injected_fake_lifecycle_v2_recovery_intent(
            envelope=authenticated,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )
        assert recovery.require_authenticated_lifecycle_v2_recovery_intent(intent) is intent
        repository.retain_recovery_classification_intent(intent)
        repository.publish_transcript()
        outcome, _commit = repository.commit_recovery_outcome(
            clock=_Clock([root.admission_started_boottime_ns]),
            created_at_utc=UTC_TEXT,
        )
    finally:
        record_defaults["_canonicalize"] = original_canonicalizer

    assert intent.recovery_classification_envelope_sha256 == authenticated.sha256
    assert (
        intent.record.evidence.to_dict()["recovery_classification_envelope_sha256"]
        == authenticated.sha256
    )
    assert intent.record.evidence.to_dict()["reason_code"] == "deadline_expired"
    assert outcome.to_dict()["reason_code"] == "deadline_expired"


def test_recovery_builder_defaults_cannot_cross_fake_intent_into_production_record() -> None:
    test_root, test_transcript = _classified_recovery_inputs()
    production_root, production_transcript = _classified_recovery_inputs(
        environment="production"
    )
    production_envelope = _recovery_envelope(
        production_root,
        production_transcript,
        reason="source_stop_unconfirmed",
        nonce=b"P" * 32,
    )
    fake_builder = recovery._build_injected_fake_lifecycle_v2_recovery_intent
    fake_closure = dict(
        zip(
            fake_builder.__code__.co_freevars,
            fake_builder.__closure__ or (),
            strict=True,
        )
    )
    build_intent = fake_closure["build_intent_value"].cell_contents
    build_closure = dict(
        zip(
            build_intent.__code__.co_freevars,
            build_intent.__closure__ or (),
            strict=True,
        )
    )
    original_build_intent = build_closure["original_build_intent_value"].cell_contents
    build_defaults = original_build_intent.__kwdefaults__
    assert build_defaults is not None
    record_builder = build_defaults["_record_builder"]
    record_defaults = record_builder.__kwdefaults__
    assert record_defaults is not None
    original_canonicalizer = record_defaults["_canonicalize"]

    def substitute_production_inputs(
        **_kwargs: object,
    ) -> tuple[
        LifecycleV2RecoveryClassificationEnvelope,
        LifecycleV2Root,
        Any,
    ]:
        return production_envelope, production_root, production_transcript

    try:
        record_defaults["_canonicalize"] = substitute_production_inputs
        intent = _fake_recovery_intent(test_root, test_transcript)
        assert recovery.require_authenticated_lifecycle_v2_recovery_intent(intent) is intent
        with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="exact test root"):
            fake_builder(
                envelope=production_envelope,
                root=production_root,
                classified_transcript=production_transcript,
                recorded_at_utc=UTC_TEXT,
            )
    finally:
        record_defaults["_canonicalize"] = original_canonicalizer

    evidence = intent.record.evidence.to_dict()
    assert intent.root_sha256 == test_root.sha256
    assert intent.record.root_sha256 == test_root.sha256
    assert evidence["recovery_classification_envelope_sha256"] != production_envelope.sha256
    assert evidence["reason_code"] == "call_or_result_ambiguous"


def test_recovery_commit_rejects_direct_repository_record_state_injection() -> None:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository = _repository(FakeLifecycleV2ArtifactStore())
    repository.reserve_root(root)
    repository.retain_request_intent(_request_intent(root, basis), basis)
    transcript = repository.publish_transcript()
    unauthenticated_record = recovery._recovery_intent_record(
        envelope=_recovery_envelope(root, transcript, reason="lock_lost"),
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )

    repository._records = (*repository._records, unauthenticated_record)
    repository.publish_transcript()

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="authenticated recovery intent",
    ):
        repository.commit_recovery_outcome(
            clock=_Clock([root.admission_started_boottime_ns]),
            created_at_utc=UTC_TEXT,
        )


def test_recovery_finalization_rejects_direct_outcome_state_injection() -> None:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    request = _request_intent(root, basis)

    source = _repository(FakeLifecycleV2ArtifactStore())
    source.reserve_root(root)
    source.retain_request_intent(request, basis)
    source_transcript = source.publish_transcript()
    source.retain_recovery_classification_intent(
        _fake_recovery_intent(root, source_transcript, reason="deadline_expired")
    )
    source.publish_transcript()
    outcome, _commit = source.commit_recovery_outcome(
        clock=_Clock([root.admission_started_boottime_ns]),
        created_at_utc=UTC_TEXT,
    )

    target_root = core_module.decode_lifecycle_v2_root(root.encoded)
    assert target_root == root
    assert target_root is not root
    target_basis = LifecycleV2CleanStopRequestBasis.from_root(target_root)
    target_store = FakeLifecycleV2ArtifactStore()
    target = _repository(target_store)
    target.reserve_root(target_root)
    target.retain_request_intent(_request_intent(target_root, target_basis), target_basis)
    target.publish_transcript()
    target._outcome = outcome

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="retained candidate",
    ):
        target.finalize_retained_outcome_commit()
    assert LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME not in target_store.inventory().names


def test_recovery_consumer_slot_replacement_cannot_replay_consumed_intent() -> None:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    request = _request_intent(root, basis)

    first = _repository(FakeLifecycleV2ArtifactStore())
    first.reserve_root(root)
    first.retain_request_intent(request, basis)
    classified = first.publish_transcript()
    intent = _fake_recovery_intent(root, classified)
    first.retain_recovery_classification_intent(intent)

    second_root = core_module.decode_lifecycle_v2_root(root.encoded)
    assert second_root == root
    assert second_root is not root
    second = _repository(FakeLifecycleV2ArtifactStore())
    second.reserve_root(second_root)
    second.retain_request_intent(
        request,
        LifecycleV2CleanStopRequestBasis.from_root(second_root),
    )
    assert second.publish_transcript() == classified
    with suppress(AttributeError):
        second._consume_recovery_intent = lambda value: value

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="invalid or already consumed",
    ):
        second.retain_recovery_classification_intent(intent)


def test_recovery_authorization_cannot_be_redirected_to_an_empty_store() -> None:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    request = _request_intent(root, basis)
    source_store = FakeLifecycleV2ArtifactStore()
    repository = _repository(source_store)
    repository.reserve_root(root)
    repository.retain_request_intent(request, basis)
    classified = repository.publish_transcript()
    repository.retain_recovery_classification_intent(
        _fake_recovery_intent(root, classified)
    )

    target_store = FakeLifecycleV2ArtifactStore()
    assert target_store.identity == repository.artifact_store_identity
    try:
        repository._store = target_store
    except AttributeError:
        assert target_store.inventory().names == ()
        return
    repository.publish_transcript()
    with pytest.raises(
        (
            persistence.LifecycleV2RepositoryRejected,
            persistence.LifecycleV2RetentionUnconfirmed,
        )
    ):
        repository.commit_recovery_outcome(
            clock=_Clock([root.admission_started_boottime_ns]),
            created_at_utc=UTC_TEXT,
        )
    assert LIFECYCLE_ROOT_FILE_NAME not in target_store.inventory().names
    assert not any("-record-" in name for name in target_store.inventory().names)
    assert LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME not in target_store.inventory().names


def test_reopened_state_transfer_cannot_authorize_confirmed_success() -> None:
    store = _SealedLineageArtifactStore()
    live, root, lineage = _complete_sealed_success_prefix(store)
    initial = {
        name: store.read_stable(name).encoded for name in store.inventory().names
    }
    reopened = _repository(_SealedLineageArtifactStore(initial=initial))
    assert reopened._opened_with_existing_root is True
    assert reopened._root == live._root
    assert reopened._root is not live._root
    assert reopened._records == live._records
    assert any(
        decoded is not retained
        for decoded, retained in zip(
            reopened._records,
            live._records,
            strict=True,
        )
    )

    reopened._opened_with_existing_root = False
    reopened._root = live._root
    reopened._records = live._records

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="live newly reserved root",
    ):
        reopened.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock(
                [
                    root.admission_started_boottime_ns + 100,
                    root.admission_started_boottime_ns + 101,
                ]
            ),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )


def test_unpoisoning_repository_flags_cannot_restore_marker_authority() -> None:
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="commit", phase="before")
    )
    repository, root = _recovery_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_recovery_outcome(
            clock=_Clock([root.admission_started_boottime_ns]),
            created_at_utc=UTC_TEXT,
        )
    assert repository._poisoned is True
    assert repository._outcome is not None
    assert repository._commit is None
    repository.close()
    assert repository._closed is True

    repository._poisoned = False
    repository._closed = False
    repository._store_disposed = False
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="one exact retained candidate",
    ):
        repository.finalize_retained_outcome_commit()


def test_loaded_candidate_cannot_gain_marker_authority_in_another_store() -> None:
    source_store = FakeLifecycleV2ArtifactStore()
    source, root = _recovery_prefix(source_store)
    outcome, _commit = source.commit_recovery_outcome(
        clock=_Clock([root.admission_started_boottime_ns]),
        created_at_utc=UTC_TEXT,
    )
    initial = {
        name: source_store.read_stable(name).encoded
        for name in source_store.inventory().names
        if name != LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME
    }
    assert outcome.file_name in initial

    target_store = FakeLifecycleV2ArtifactStore(initial=initial)
    assert target_store is not source_store
    assert target_store.identity == source_store.identity
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="publication history",
    ):
        _repository(target_store)
    assert LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME not in target_store.inventory().names


def test_completed_candidate_history_cannot_be_restored_by_repository_flags() -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository, root = _recovery_prefix(store)
    outcome, commit = repository.commit_recovery_outcome(
        clock=_Clock([root.admission_started_boottime_ns]),
        created_at_utc=UTC_TEXT,
    )
    marker_encoded = store.read_stable(
        LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME
    ).encoded
    assert commit.to_dict()["outcome_sha256"] == outcome.sha256

    repository._commit = None
    repository._poisoned = False
    repository._closed = False
    repository._store_disposed = False
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="one exact retained candidate",
    ):
        repository.finalize_retained_outcome_commit()
    assert (
        store.read_stable(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME).encoded
        == marker_encoded
    )


def test_docker_result_rule_replacement_cannot_authorize_durable_recovery_prefix() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    original = lineage.record_at(8)
    evidence = original.evidence.to_dict()
    semantic = cast(dict[str, object], evidence["result_semantic"])
    semantic["outcome"] = "attacker_outcome"
    evidence["disposition"] = "attacker_outcome"
    evidence["result_semantic_sha256"] = core_module._nested_domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/"
        "docker-container-stop-result/v2",
        semantic,
    )
    original_rules = core_module._DOCKER_RESULT_RULE_BY_STAGE
    if type(original_rules) is dict:
        malicious_rules: object = dict(original_rules)
        original_rule = malicious_rules[original.stage]  # type: ignore[index]
        malicious_rules[original.stage] = (  # type: ignore[index]
            *original_rule[:4],
            "attacker_outcome",
            *original_rule[5:],
        )
    else:
        malicious_items: list[tuple[object, object]] = []
        for stage, rule in cast(tuple[tuple[object, object], ...], original_rules):
            if stage is original.stage:
                if hasattr(rule, "_replace"):
                    rule = rule._replace(outcome="attacker_outcome")
                else:
                    rule = (*rule[:4], "attacker_outcome", *rule[5:])
            malicious_items.append((stage, rule))
        malicious_rules = tuple(malicious_items)

    core_module._DOCKER_RESULT_RULE_BY_STAGE = malicious_rules
    try:
        try:
            forged = LifecycleV2ProgressRecord(
                graceful_stop_operation_id=original.graceful_stop_operation_id,
                root_sha256=original.root_sha256,
                ordinal=original.ordinal,
                stage=original.stage,
                predecessor_sha256=original.predecessor_sha256,
                effect_kind=original.effect_kind,
                deadline_boottime_ns=original.deadline_boottime_ns,
                evidence=FrozenJsonObject.capture(evidence),
                recorded_at_utc=original.recorded_at_utc,
            )
        except TrustedTimeGracefulStopV2Rejected:
            return

        store = _SealedLineageArtifactStore()
        repository = _retain_sealed_success_prefix(
            store,
            scenario,
            lineage,
            through_ordinal=7,
        )
        try:
            repository.retain_effect_result(forged)
        except persistence.LifecycleV2RepositoryRejected:
            return
        classified = repository.publish_transcript()
        try:
            repository.retain_recovery_classification_intent(
                _fake_recovery_intent(scenario.root, classified)
            )
        except persistence.LifecycleV2RepositoryRejected:
            return
        repository.publish_transcript()
        with pytest.raises(
            (
                persistence.LifecycleV2RepositoryRejected,
                persistence.LifecycleV2RetentionUnconfirmed,
            )
        ):
            repository.commit_recovery_outcome(
                clock=_Clock([scenario.root.admission_started_boottime_ns]),
                created_at_utc=UTC_TEXT,
            )
    finally:
        core_module._DOCKER_RESULT_RULE_BY_STAGE = original_rules


def test_normal_stage_rule_mutation_cannot_authorize_durable_recovery_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    authentic = lineage.record_at(3)
    reordered = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=authentic.graceful_stop_operation_id,
        root_sha256=authentic.root_sha256,
        ordinal=2,
        stage=authentic.stage,
        predecessor_sha256=scenario.request_intent.sha256,
        effect_kind=authentic.effect_kind,
        deadline_boottime_ns=authentic.deadline_boottime_ns,
        evidence=authentic.evidence,
        recorded_at_utc=authentic.recorded_at_utc,
    )
    rules = core_module.NORMAL_STAGE_BY_ORDINAL
    if type(rules) is dict:
        malicious_rules: object = dict(rules)
        cast(dict[int, LifecycleV2Stage], malicious_rules)[2] = (
            LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED
        )
    else:
        assert type(rules) is tuple
        malicious_rules = (
            *rules[:2],
            LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
            *rules[3:],
        )

    def malicious_lookup(ordinal: int) -> LifecycleV2Stage | None:
        if ordinal == 2:
            return LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED
        if type(rules) is dict:
            return cast(dict[int, LifecycleV2Stage], rules).get(ordinal)
        if 0 <= ordinal < len(rules):
            return rules[ordinal]
        return None

    monkeypatch.setattr(core_module, "NORMAL_STAGE_BY_ORDINAL", malicious_rules)
    monkeypatch.setattr(
        persistence,
        "normal_lifecycle_v2_stage_for_ordinal",
        malicious_lookup,
    )
    monkeypatch.setattr(
        recovery,
        "normal_lifecycle_v2_stage_for_ordinal",
        malicious_lookup,
    )
    transition_validator = persistence._LifecycleV2Repository._require_stage_transition
    monkeypatch.setattr(
        transition_validator,
        "__defaults__",
        (malicious_lookup,),
    )
    monkeypatch.setattr(
        transition_validator,
        "__kwdefaults__",
        {"records": None, "_normal_stage_for_ordinal": malicious_lookup},
    )
    prefix_validator = recovery._require_prefix_stage
    monkeypatch.setattr(prefix_validator, "__defaults__", (malicious_lookup,))
    monkeypatch.setattr(
        prefix_validator,
        "__kwdefaults__",
        {"_normal_stage_for_ordinal": malicious_lookup},
    )

    repository = _repository(FakeLifecycleV2ArtifactStore())
    basis = LifecycleV2CleanStopRequestBasis.from_root(scenario.root)
    repository.reserve_root(scenario.root)
    repository.retain_request_intent(scenario.request_intent, basis)
    try:
        repository.retain_transport_cleanup_commitment(reordered)
    except persistence.LifecycleV2RepositoryRejected:
        return
    classified = repository.publish_transcript()
    try:
        repository.retain_recovery_classification_intent(
            _fake_recovery_intent(scenario.root, classified)
        )
    except persistence.LifecycleV2RepositoryRejected:
        return
    repository.publish_transcript()
    with pytest.raises(
        (
            persistence.LifecycleV2RepositoryRejected,
            persistence.LifecycleV2RetentionUnconfirmed,
        )
    ):
        repository.commit_recovery_outcome(
            clock=_Clock([scenario.root.admission_started_boottime_ns]),
            created_at_utc=UTC_TEXT,
        )


def test_repository_ignores_replaced_recovery_consumer_globals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classified_root, transcript = _classified_recovery_inputs()
    root = core_module.decode_lifecycle_v2_root(classified_root.encoded)
    assert root == classified_root
    assert root is not classified_root
    repository = _repository(FakeLifecycleV2ArtifactStore())
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository.reserve_root(root)
    repository.retain_request_intent(_request_intent(root, basis), basis)
    repository.publish_transcript()
    authentic = _fake_recovery_intent(root, transcript)
    forged = copy.copy(authentic)
    assert forged is not authentic
    monkeypatch.setattr(
        persistence,
        "require_authenticated_lifecycle_v2_recovery_intent",
        lambda value: value,
        raising=False,
    )
    monkeypatch.setattr(
        persistence,
        "consume_authenticated_lifecycle_v2_recovery_intent",
        lambda value: value,
        raising=False,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="not authenticated",
    ):
        repository.retain_recovery_classification_intent(forged)

    assert repository.retain_recovery_classification_intent(authentic) == authentic.record


def test_fake_recovery_intent_consumption_is_thread_bound_and_one_use() -> None:
    root, transcript = _classified_recovery_inputs()
    intent = _fake_recovery_intent(root, transcript)
    failures: list[BaseException] = []

    def consume_on_wrong_thread() -> None:
        try:
            recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent)
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=consume_on_wrong_thread)
    worker.start()
    worker.join()

    assert len(failures) == 1
    assert type(failures[0]) is TrustedTimeGracefulStopV2Rejected
    assert recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent) is intent
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already consumed"):
        recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent)


def test_recovery_intent_owner_cannot_be_spoofed_through_module_globals() -> None:
    root, transcript = _classified_recovery_inputs()
    intent = _fake_recovery_intent(root, transcript)
    owner_thread = threading.current_thread()
    original_threading = recovery.threading
    failures: list[BaseException] = []

    def consume_with_spoofed_owner() -> None:
        recovery.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent)
        except BaseException as error:
            failures.append(error)
        finally:
            recovery.threading = original_threading

    worker = threading.Thread(target=consume_with_spoofed_owner)
    worker.start()
    worker.join()

    assert len(failures) == 1
    assert type(failures[0]) is TrustedTimeGracefulStopV2Rejected
    assert recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent) is intent


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork ownership proof")
def test_fake_recovery_intent_consumption_is_fork_bound() -> None:
    root, transcript = _classified_recovery_inputs()
    intent = _fake_recovery_intent(root, transcript)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent)
        except TrustedTimeGracefulStopV2Rejected:
            os.write(write_fd, b"rejected")
        else:
            os.write(write_fd, b"accepted")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    child_result = os.read(read_fd, 32)
    os.close(read_fd)
    _, status = os.waitpid(child, 0)

    assert os.waitstatus_to_exitcode(status) == 0
    assert child_result == b"rejected"
    assert recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent) is intent


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork ownership proof")
def test_recovery_intent_fork_owner_cannot_be_spoofed_through_module_globals() -> None:
    root, transcript = _classified_recovery_inputs()
    intent = _fake_recovery_intent(root, transcript)
    parent_pid = os.getpid()
    owner_thread = threading.current_thread()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        recovery.os = SimpleNamespace(getpid=lambda: parent_pid)  # type: ignore[assignment]
        recovery.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent)
        except TrustedTimeGracefulStopV2Rejected:
            os.write(write_fd, b"rejected")
        else:
            os.write(write_fd, b"accepted")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    child_result = os.read(read_fd, 32)
    os.close(read_fd)
    _, status = os.waitpid(child, 0)

    assert os.waitstatus_to_exitcode(status) == 0
    assert child_result == b"rejected"
    assert recovery.consume_authenticated_lifecycle_v2_recovery_intent(intent) is intent


def test_repository_owner_cannot_be_spoofed_through_module_globals() -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    root = _root()
    repository.reserve_root(root)
    owner_thread = threading.current_thread()
    owner_pid = os.getpid()
    original_os = persistence.os
    original_threading = persistence.threading
    failures: list[BaseException] = []

    def read_status_with_spoofed_owner() -> None:
        persistence.os = SimpleNamespace(getpid=lambda: owner_pid)  # type: ignore[assignment]
        persistence.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            _ = repository.status
        except BaseException as error:
            failures.append(error)
        finally:
            persistence.os = original_os
            persistence.threading = original_threading

    worker = threading.Thread(target=read_status_with_spoofed_owner)
    worker.start()
    worker.join()

    assert len(failures) == 1
    assert type(failures[0]) is persistence.LifecycleV2RetentionUnconfirmed
    assert repository.status is persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork ownership proof")
def test_repository_fork_owner_cannot_be_spoofed_through_module_globals() -> None:
    repository = _repository(FakeLifecycleV2ArtifactStore())
    root = _root()
    repository.reserve_root(root)
    parent_pid = os.getpid()
    owner_thread = threading.current_thread()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        persistence.os = SimpleNamespace(getpid=lambda: parent_pid)  # type: ignore[assignment]
        persistence.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            _ = repository.status
        except persistence.LifecycleV2RetentionUnconfirmed:
            os.write(write_fd, b"rejected")
        else:
            os.write(write_fd, b"accepted")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    child_result = os.read(read_fd, 32)
    os.close(read_fd)
    _, status = os.waitpid(child, 0)

    assert os.waitstatus_to_exitcode(status) == 0
    assert child_result == b"rejected"
    assert repository.status is persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED


def test_production_recovery_nonce_replay_is_independent_of_pid_globals() -> None:
    from packages.adapters.trusted_time.graceful_stop_v2_ed25519 import (
        consume_authenticated_lifecycle_v2_recovery_classification_envelope,
    )
    from tests.unit import test_trusted_time_graceful_stop_v2_transport_contracts as transport_fx

    nonce = bytes(range(96, 128))
    first, root, transcript, _ = transport_fx._authenticated_recovery_for_consumption(
        nonce=nonce,
    )
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    intent = transport_fx._intent(root)
    first_repository = _repository(FakeLifecycleV2ArtifactStore())
    first_repository.reserve_root(root)
    first_repository.retain_request_intent(intent, basis)
    assert first_repository.publish_transcript() == transcript
    first_recovery = (
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            first,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )
    )
    first_repository.retain_recovery_classification_intent(first_recovery)
    derive_closure = dict(
        zip(
            recovery._derive_authenticated_lifecycle_v2_recovery_intent.__code__.co_freevars,
            recovery._derive_authenticated_lifecycle_v2_recovery_intent.__closure__
            or (),
            strict=True,
        )
    )
    reserve_nonce = derive_closure["reserve_production_nonce"].cell_contents
    reserve_closure = dict(
        zip(
            reserve_nonce.__code__.co_freevars,
            reserve_nonce.__closure__ or (),
            strict=True,
        )
    )
    nonce_state = reserve_closure["nonce_state"].cell_contents
    expected_nonce_key = (root.sha256, hashlib.sha256(nonce).hexdigest())
    assert expected_nonce_key in nonce_state
    assert not any(
        type(referent) in {dict, list, set, bytearray}
        for referent in gc.get_referents(nonce_state)
    )

    second, second_root, second_transcript, _ = (
        transport_fx._authenticated_recovery_for_consumption(nonce=nonce)
    )
    second_repository = _repository(FakeLifecycleV2ArtifactStore())
    second_repository.reserve_root(second_root)
    second_repository.retain_request_intent(transport_fx._intent(second_root), basis)
    assert second_repository.publish_transcript() == second_transcript
    original_os = recovery.os
    recovery.os = SimpleNamespace(getpid=lambda: os.getpid() + 100_000)  # type: ignore[assignment]
    try:
        with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already consumed"):
            consume_authenticated_lifecycle_v2_recovery_classification_envelope(
                second,
                root=second_root,
                classified_transcript=second_transcript,
                recorded_at_utc=UTC_TEXT,
            )
    finally:
        recovery.os = original_os

    assert second_repository.status is persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED


@pytest.mark.parametrize("reason", sorted(RECOVERY_CLASSIFICATION_REASON_CODES))
def test_recovery_intent_and_outcome_are_derived_for_every_reason(reason: str) -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository, root = _recovery_prefix(store, reason=reason)

    outcome, commit = repository.commit_recovery_outcome(
        clock=_Clock([root.operation_deadline_boottime_ns + 10]),
        created_at_utc=UTC_TEXT,
    )

    assert outcome.status == "recovery_required"
    assert outcome.to_dict()["reason_code"] == reason
    assert commit.to_dict()["commit_authorized_boottime_ns"] == (
        root.operation_deadline_boottime_ns + 10
    )
    assert repository.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMITTED


def test_recovery_candidate_alone_can_finalize_only_that_exact_candidate() -> None:
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="commit", phase="before")
    )
    repository, root = _recovery_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_recovery_outcome(
            clock=_Clock([root.operation_deadline_boottime_ns + 10]),
            created_at_utc=UTC_TEXT,
        )

    reopened = _repository(store)
    assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
    commit = reopened.finalize_retained_outcome_commit()
    assert commit.to_dict()["outcome_status"] == "recovery_required"
    assert reopened.finalize_retained_outcome_commit() == commit


@pytest.mark.parametrize(
    "phase",
    ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced", "readback"],
)
def test_exact_recovery_marker_staging_is_restart_finalizable(phase: str) -> None:
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="commit", phase=phase)
    )
    repository, root = _recovery_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_recovery_outcome(
            clock=_Clock([root.operation_deadline_boottime_ns + 10]),
            created_at_utc=UTC_TEXT,
        )

    reopened = _repository(store)
    if phase in {"renamed", "directory_fsynced", "readback"}:
        assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMITTED
    else:
        assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
    if phase == "renamed":
        assert [event for event in store.events if event.startswith("commit_finalize:")] == [
            "commit_finalize:before",
            "commit_finalize:file_fsynced",
            "commit_finalize:directory_fsynced",
            "commit_finalize:readback",
            "commit_finalize:revalidated",
        ]
    commit = reopened.finalize_retained_outcome_commit()
    assert commit.to_dict()["outcome_status"] == "recovery_required"


@pytest.mark.parametrize("phase", ["file_fsynced", "directory_fsynced", "readback"])
def test_restart_fixed_marker_durability_uncertainty_burns_closed(phase: str) -> None:
    original_store = FakeLifecycleV2ArtifactStore()
    repository, root = _recovery_prefix(original_store)
    repository.commit_recovery_outcome(
        clock=_Clock([root.operation_deadline_boottime_ns + 10]),
        created_at_utc=UTC_TEXT,
    )
    initial = {
        name: original_store.read_stable(name).encoded for name in original_store.inventory().names
    }
    original_store.close()
    reopening_store = FakeLifecycleV2ArtifactStore(
        initial=initial,
        fault=FakePublicationFault(operation="commit_finalize", phase=phase),
    )

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(reopening_store)

    assert reopening_store.close_count == 1
    assert LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME in reopening_store.inventory().names


def test_caller_constructed_raw_progress_prefix_cannot_authorize_success() -> None:
    store = _SealedLineageArtifactStore()
    repository, root = _complete_raw_success_prefix(store)
    forged_lineage = object.__new__(LifecycleV2NormalProgressLineage)

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="sealed exact ordinal-22 lineage",
    ):
        repository.commit_confirmed_success(
            lineage=forged_lineage,
            clock=_Clock([root.admission_started_boottime_ns + 100]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    assert not any("outcome-" in name for name in store.inventory().names)


def test_confirmed_success_ignores_replaced_consumer_globals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _SealedLineageArtifactStore()
    repository, root = _complete_raw_success_prefix(store)
    monkeypatch.setattr(
        persistence,
        "consume_exact_lifecycle_v2_confirmed_success_lineage",
        lambda value: value,
        raising=False,
    )
    monkeypatch.setattr(
        persistence,
        "consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository",
        lambda value: value,
        raising=False,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="sealed exact ordinal-22 lineage",
    ):
        repository.commit_confirmed_success(
            lineage=object(),
            clock=_Clock([root.admission_started_boottime_ns + 100]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    assert not any("outcome-" in name for name in store.inventory().names)


def test_confirmed_success_rejects_an_authentic_lineage_from_another_root() -> None:
    store = _SealedLineageArtifactStore()
    repository, root = _complete_raw_success_prefix(store)
    scenario = _scenario()
    other_lineage = _complete_lineage(scenario)

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="retained repository prefix disagree",
    ):
        repository.commit_confirmed_success(
            lineage=other_lineage,
            clock=_Clock([root.admission_started_boottime_ns + 100]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    assert not any("outcome-" in name for name in store.inventory().names)


def test_confirmed_success_rejects_same_root_canonical_record_substitution() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    store = _SealedLineageArtifactStore()
    repository = _retain_sealed_success_prefix(
        store,
        scenario,
        lineage,
        clone_ordinal=6,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="retained repository prefix disagree",
    ):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([scenario.root.admission_started_boottime_ns + 100]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    assert not any("outcome-" in name for name in store.inventory().names)


def test_mutated_sealed_lineage_cannot_authorize_success() -> None:
    store = _SealedLineageArtifactStore()
    repository, root, lineage = _complete_sealed_success_prefix(store)
    object.__setattr__(lineage, "records", (*lineage.records[:-1], lineage.records[-2]))

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="sealed exact ordinal-22 lineage",
    ):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([root.admission_started_boottime_ns + 100]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    assert not any("outcome-" in name for name in store.inventory().names)


def test_first_success_store_attempt_cannot_transfer_to_equal_root_repository() -> None:
    scenario = _scenario()
    lineage = _complete_lineage(scenario)
    first_store = _SealedLineageArtifactStore(
        fault=FakePublicationFault(operation="outcome", phase="before")
    )
    second_scenario = _scenario()
    second_lineage = _complete_lineage(second_scenario)
    assert second_scenario.root == scenario.root
    assert second_scenario.root is not scenario.root
    second_store = _SealedLineageArtifactStore()
    first = _retain_sealed_success_prefix(first_store, scenario, lineage)
    second = _retain_sealed_success_prefix(
        second_store,
        second_scenario,
        second_lineage,
    )
    second_records = second._records
    sample = scenario.root.admission_started_boottime_ns + 100

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        first.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([sample]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )
    second._records = first._records
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="sealed exact ordinal-22 lineage",
    ):
        second.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([sample]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    second._records = second_records
    outcome, _commit = second.commit_confirmed_success(
        lineage=second_lineage,
        clock=_Clock([sample, sample + 1]),
        precommit_disposer=_Disposer(),
        created_at_utc=UTC_TEXT,
    )
    assert outcome.status == "confirmed_success"


def test_confirmed_success_orders_readback_disposal_final_sample_then_marker() -> None:
    events: list[str] = []
    store = _TraceStore(events)
    repository, root, lineage = _complete_sealed_success_prefix(store)
    protocol_start = root.operation_deadline_boottime_ns - 2

    outcome, commit = repository.commit_confirmed_success(
        lineage=lineage,
        clock=_Clock([protocol_start, root.operation_deadline_boottime_ns - 1], events),
        precommit_disposer=_Disposer(events=events),
        created_at_utc=UTC_TEXT,
    )

    assert outcome.status == "confirmed_success"
    assert outcome.to_dict()["commit_authorized_boottime_ns"] is None
    assert commit.to_dict()["commit_authorized_boottime_ns"] == (
        root.operation_deadline_boottime_ns - 1
    )
    assert events[-6:] == [
        "clock",
        "candidate_publish",
        "candidate_readback",
        "dispose",
        "clock",
        "marker_publish",
    ]


@pytest.mark.parametrize("at_cutoff", ["commit_window", "operation"])
def test_confirmed_success_equality_is_expired_after_candidate_readback(
    at_cutoff: str,
) -> None:
    store = _SealedLineageArtifactStore()
    repository, root, lineage = _complete_sealed_success_prefix(store)
    protocol_start = root.operation_deadline_boottime_ns - 10_000_000_000
    final_sample = (
        protocol_start + 5_000_000_000
        if at_cutoff == "commit_window"
        else root.operation_deadline_boottime_ns
    )

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="equality-expired",
    ):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([protocol_start, final_sample]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    reopened = _repository(store)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="lacks an authenticated marker preimage",
    ):
        reopened.finalize_retained_outcome_commit()


@pytest.mark.parametrize(
    "final_sample",
    [True, RuntimeError("CLOCK_BOOTTIME unavailable")],
)
def test_confirmed_success_final_clock_failure_seals_candidate_as_unconfirmed(
    final_sample: object,
) -> None:
    store = _SealedLineageArtifactStore()
    repository, root, lineage = _complete_sealed_success_prefix(store)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="final CLOCK_BOOTTIME",
    ):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock([root.admission_started_boottime_ns + 100, final_sample]),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    reopened = _repository(store)
    assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="lacks an authenticated marker preimage",
    ):
        reopened.finalize_retained_outcome_commit()


@pytest.mark.parametrize("field", ["descriptor", "registry"])
def test_nonempty_precommit_owner_projection_cannot_publish_marker(field: str) -> None:
    store = _SealedLineageArtifactStore()
    repository, root, lineage = _complete_sealed_success_prefix(store)
    disposer = _Disposer(
        descriptor_count=1 if field == "descriptor" else 0,
        registry_count=1 if field == "registry" else 0,
    )

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed, match="not empty"):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock(
                [
                    root.admission_started_boottime_ns + 100,
                    root.admission_started_boottime_ns + 101,
                ]
            ),
            precommit_disposer=disposer,
            created_at_utc=UTC_TEXT,
        )
    assert LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME not in store.inventory().names


@pytest.mark.parametrize(
    "phase",
    ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced", "readback"],
)
def test_success_marker_fault_allows_only_exact_preimage_revalidation(phase: str) -> None:
    store = _SealedLineageArtifactStore(fault=FakePublicationFault(operation="commit", phase=phase))
    repository, root, lineage = _complete_sealed_success_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock(
                [
                    root.admission_started_boottime_ns + 100,
                    root.admission_started_boottime_ns + 101,
                ]
            ),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    reopened = _repository(store)
    if phase == "before":
        with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="lacks"):
            reopened.finalize_retained_outcome_commit()
    elif phase in {"staging_created", "file_fsynced"}:
        commit = reopened.finalize_retained_outcome_commit()
        assert commit.to_dict()["outcome_status"] == "confirmed_success"
    else:
        assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMITTED


@pytest.mark.parametrize(
    "phase",
    ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced", "readback"],
)
def test_candidate_fault_never_permits_a_second_or_dual_outcome(phase: str) -> None:
    store = _SealedLineageArtifactStore(
        fault=FakePublicationFault(operation="outcome", phase=phase)
    )
    repository, root, lineage = _complete_sealed_success_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_confirmed_success(
            lineage=lineage,
            clock=_Clock(
                [
                    root.admission_started_boottime_ns + 100,
                    root.admission_started_boottime_ns + 101,
                ]
            ),
            precommit_disposer=_Disposer(),
            created_at_utc=UTC_TEXT,
        )

    if phase in {"renamed", "directory_fsynced", "readback"}:
        reopened = _repository(store)
        with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="lacks"):
            reopened.finalize_retained_outcome_commit()
    elif phase == "before":
        reopened = _repository(store)
        classified = reopened.publish_transcript()
        recovered = _fake_recovery_intent(
            root,
            classified,
            reason="outcome_commit_unconfirmed",
        )
        reopened.retain_recovery_classification_intent(recovered)
        reopened.publish_transcript()
        outcome, _ = reopened.commit_recovery_outcome(
            clock=_Clock([root.operation_deadline_boottime_ns + 10]),
            created_at_utc=UTC_TEXT,
        )
        assert outcome.status == "recovery_required"
    else:
        with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
            _repository(store)


@pytest.mark.parametrize(
    "phase",
    ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced", "readback"],
)
def test_recovery_candidate_fault_never_permits_a_second_or_dual_outcome(
    phase: str,
) -> None:
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="outcome", phase=phase)
    )
    repository, root = _recovery_prefix(store)

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_recovery_outcome(
            clock=_Clock([root.operation_deadline_boottime_ns + 10]),
            created_at_utc=UTC_TEXT,
        )

    if phase in {"staging_created", "file_fsynced"}:
        with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
            _repository(store)
        return

    reopened = _repository(store)
    if phase == "before":
        outcome, commit = reopened.commit_recovery_outcome(
            clock=_Clock([root.operation_deadline_boottime_ns + 11]),
            created_at_utc=UTC_TEXT,
        )
        assert outcome.status == "recovery_required"
        assert commit.to_dict()["outcome_status"] == "recovery_required"
        return

    assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
    commit = reopened.finalize_retained_outcome_commit()
    assert commit.to_dict()["outcome_status"] == "recovery_required"


def test_boolean_and_missing_boottime_samples_fail_closed() -> None:
    for samples in ([True], [RuntimeError("clock")]):
        store = FakeLifecycleV2ArtifactStore()
        repository, _ = _recovery_prefix(store)
        with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="CLOCK_BOOTTIME"):
            repository.commit_recovery_outcome(
                clock=_Clock(samples),
                created_at_utc=UTC_TEXT,
            )
        assert not any("outcome-" in name for name in store.inventory().names)
