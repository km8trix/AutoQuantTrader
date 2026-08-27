from __future__ import annotations

import ast
import copy
import hashlib
import os
import pickle
import threading
from pathlib import Path
from typing import cast

import pytest

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    LifecycleV2TranscriptEntry,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
)
from packages.domain.trusted_time_graceful_stop_v2_reauthentication import (
    _FAKE_OBSERVATION_CAPABILITY,
    ADR0109_OBSERVATION_BUDGET_NS,
    ADR0109_REAUTHENTICATION_CONTRACT_VERSION,
    ADR0109_REAUTHENTICATION_STATUS,
    LifecycleV2ADR0109ObservationPrimitives,
    LifecycleV2AuthenticatedADR0109Observation,
    LifecycleV2PostTeardownBinding,
    LifecycleV2PostTeardownBindingEvidence,
    LifecycleV2PreEffectBinding,
    LifecycleV2PreEffectBindingEvidence,
    _bind_lifecycle_v2_post_teardown_observation_once,
    _bind_lifecycle_v2_pre_effect_observation_once,
    _LifecycleV2PostTeardownBindingIssuer,
    _LifecycleV2PreEffectBindingIssuer,
    _mint_fake_authenticated_adr0109_observation,
    _prepare_lifecycle_v2_post_teardown_binding_issuer,
    _prepare_lifecycle_v2_pre_effect_binding_issuer,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    CLEAN_STOP_RESULT_CONTRACT_VERSION,
    LISTENER_PATH,
    SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
    SUPERVISOR_RAW_KEY_PATH,
    LifecycleV2CleanStopResult,
    LifecycleV2SupervisorCleanupCommitment,
    LifecycleV2TerminalProjection,
)

ENVIRONMENT = "test"
OPERATION_ID = "323e4567-e89b-42d3-a456-426614174099"
SUPERVISOR_ID = "1" * 64
SOURCE_ID = "2" * 64
NETWORK_ID = "3" * 64
UTC_TEXT = "2026-08-27T12:00:00.000000Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _root(*, suffix: str = "") -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=(OPERATION_ID if not suffix else f"other-{suffix}"),
        graceful_stop_target_sha256=_digest(f"target{suffix}"),
        graceful_stop_decision_v1_sha256=_digest(f"decision{suffix}"),
        graceful_stop_operator_attestation_envelope_sha256=_digest(
            f"attestation{suffix}"
        ),
        historical_decision_receipt_sha256=_digest(f"receipt{suffix}"),
        admission_sha256=_digest(f"admission{suffix}"),
        topology_sha256=_digest(f"topology{suffix}"),
        topology_lease_sha256=_digest(f"topology-lease{suffix}"),
        trusted_head_sha256=_digest(f"head{suffix}"),
        stop_authority_sha256=_digest(f"authority{suffix}"),
        transport_authority_manifest_sha256=_digest(f"manifest{suffix}"),
        transport_key_generation=1,
        host_transport_key_id="host-key-1",
        supervisor_transport_key_id="supervisor-key-1",
        boot_epoch_sha256=_digest(f"boot{suffix}"),
        host_process_epoch_sha256=_digest(f"host-process{suffix}"),
        supervisor_process_epoch_sha256=_digest(f"supervisor-process{suffix}"),
        channel_id=_digest(f"channel{suffix}"),
        supervisor_container_id=SUPERVISOR_ID,
        source_container_id=SOURCE_ID,
        project_network_id=NETWORK_ID,
        chrony_command_socket_volume_identity_sha256=_digest(
            f"command-volume{suffix}"
        ),
        chrony_state_volume_identity_sha256=_digest(f"state-volume{suffix}"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request(root: LifecycleV2Root) -> LifecycleV2CleanStopRequest:
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
    return LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)


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
        "current_host_head_sha256": _digest("current-anchor"),
        "current_anchor_sha256": _digest("current-anchor"),
        "current_anchor_semantic_sha256": _digest("anchor-semantic"),
        "receipt_observed_at_utc": UTC_TEXT,
        "full_audit_completed": True,
        "prior_pending_intent_recovered": False,
        "uploaded_anchor_count": 1,
        "idempotent_duplicate_count": 0,
        "current_anchor_intent_semantic_sha256": _digest("intent-semantic"),
        "current_candidate_remote_readback_sha256": _digest("current-anchor"),
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
        canonical_v2_json_bytes(semantic, maximum_bytes=64 * 1_024)
    ).hexdigest()
    return LifecycleV2TerminalProjection.capture(value)


def _cleanup(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2SupervisorCleanupCommitment:
    return LifecycleV2SupervisorCleanupCommitment.capture(
        {
            "contract_version": SUPERVISOR_CLEANUP_COMMITMENT_CONTRACT_VERSION,
            "service": "trusted-time-graceful-stop-transport-v2",
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


def _result(
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
) -> LifecycleV2CleanStopResult:
    projection = _terminal_projection()
    cleanup = _cleanup(root, request)
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


def _quiescence(root: LifecycleV2Root) -> LifecycleV2ProgressRecord:
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=4,
        stage=LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED,
        predecessor_sha256=_digest("ordinal-3"),
        effect_kind="transport_cleanup",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "cleanup_commitment_record_sha256": _digest("cleanup-record"),
                "supervisor_cleanup_commitment_sha256": _digest("cleanup-commitment"),
                "host_native_cleanup_receipt_sha256": _digest("host-cleanup"),
                "supervisor_quiescence_observation_sha256": _digest(
                    "supervisor-quiescence"
                ),
                "channel_eof_observed": True,
                "listener_fd_absent": True,
                "accepted_fd_absent": True,
                "socket_path_absent": True,
                "host_signer_zeroized": True,
                "host_challenge_zeroized": True,
                "host_process_nonce_zeroized": True,
                "credential_paths_absent": True,
                "cleanup_started_boottime_ns": 100_000_000_000,
                "cleanup_completed_boottime_ns": 150_000_000_000,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )


def _intent(
    root: LifecycleV2Root,
    *,
    ordinal: int,
    stage: LifecycleV2Stage,
    predecessor: str,
) -> LifecycleV2ProgressRecord:
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=ordinal,
        stage=stage,
        predecessor_sha256=predecessor,
        effect_kind="reauthentication_observation",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "target_identity_sha256": _digest(f"target-{ordinal}"),
                "arguments_sha256": _digest(f"arguments-{ordinal}"),
                "admission_sha256": root.admission_sha256,
                "channel_id": root.channel_id,
                "call_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )


def _result_record(
    root: LifecycleV2Root,
    *,
    ordinal: int,
    stage: LifecycleV2Stage,
    predecessor: str,
) -> LifecycleV2ProgressRecord:
    common: dict[str, object] = {
        "intent_sha256": _digest(f"intent-{ordinal}"),
        "responder_identity_sha256": _digest("docker-daemon"),
        "disposition": "confirmed",
        "result_semantic_sha256": _digest(f"semantic-{ordinal}"),
        "call_started_boottime_ns": 300_000_000_000 + ordinal,
        "call_completed_boottime_ns": 350_000_000_000 + ordinal,
    }
    if ordinal == 18:
        common.update(
            {
                "command_socket_volume_identity_sha256": _digest("command-volume"),
                "state_volume_identity_sha256": _digest("state-volume"),
                "docker_api_trace_sha256": _digest("volume-trace"),
                "volume_delete_call_count": 0,
                "docker_request_semantic_sha256_list": [
                    _digest("volume-request-1"),
                    _digest("volume-request-2"),
                ],
                "result_semantic": {"ordinal": ordinal},
                "docker_method_trace_entry_sha256_list": [
                    _digest("volume-trace-1"),
                    _digest("volume-trace-2"),
                ],
            }
        )
    else:
        common.update(
            {
                "docker_request_semantic_sha256": _digest(f"request-{ordinal}"),
                "docker_post_inspect_request_semantic_sha256": _digest(
                    f"post-inspect-{ordinal}"
                ),
                "result_semantic": {"ordinal": ordinal},
                "docker_method_trace_entry_sha256_list": [
                    _digest(f"trace-primary-{ordinal}"),
                    _digest(f"trace-post-{ordinal}"),
                ],
            }
        )
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=ordinal,
        stage=stage,
        predecessor_sha256=predecessor,
        effect_kind="docker_result" if ordinal != 18 else "volume_preservation",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(common),
        recorded_at_utc=UTC_TEXT,
    )


_STAGES = (
    LifecycleV2Stage.ROOT_RESERVED,
    LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
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
)
_RESULT_STAGE_BY_ORDINAL = {
    8: LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
    10: LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
    12: LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
    14: LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
    16: LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
    18: LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
}


def _transcript_and_results(
    root: LifecycleV2Root,
) -> tuple[LifecycleV2Transcript, tuple[LifecycleV2ProgressRecord, ...]]:
    entries: list[LifecycleV2TranscriptEntry] = [
        LifecycleV2TranscriptEntry(
            ordinal=0,
            stage=LifecycleV2Stage.ROOT_RESERVED,
            record_artifact_kind="root",
            record_contract_version=LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
            record_artifact_sha256=root.sha256,
            predecessor_sha256=None,
        )
    ]
    result_records: list[LifecycleV2ProgressRecord] = []
    previous = root.sha256
    for ordinal in range(1, 19):
        stage = _STAGES[ordinal]
        if ordinal in _RESULT_STAGE_BY_ORDINAL:
            record = _result_record(
                root,
                ordinal=ordinal,
                stage=_RESULT_STAGE_BY_ORDINAL[ordinal],
                predecessor=previous,
            )
            digest = record.sha256
            result_records.append(record)
        else:
            digest = _digest(f"transcript-record-{ordinal}")
        wire = ordinal == 2
        entries.append(
            LifecycleV2TranscriptEntry(
                ordinal=ordinal,
                stage=stage,
                record_artifact_kind="progress",
                record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                record_artifact_sha256=digest,
                predecessor_sha256=previous,
                wire_artifact_kind=("signed_result_envelope" if wire else None),
                wire_artifact_path=("/injected/result.json" if wire else None),
                wire_artifact_file_name=("result.json" if wire else None),
                wire_artifact_sha256=(_digest("wire-result") if wire else None),
            )
        )
        previous = digest
    return (
        LifecycleV2Transcript(
            environment=root.environment,
            graceful_stop_operation_id=root.graceful_stop_operation_id,
            root_sha256=root.sha256,
            entries=tuple(entries),
        ),
        tuple(result_records),
    )


def _observation_value(
    result: LifecycleV2CleanStopResult,
    *,
    label: str,
    started: int,
    provider_suffix: str = "",
) -> dict[str, object]:
    terminal = result.terminal_projection.to_dict()
    return {
        "contract_version": ADR0109_REAUTHENTICATION_CONTRACT_VERSION,
        "status": ADR0109_REAUTHENTICATION_STATUS,
        "anchor_sequence": terminal["anchor_sequence"],
        "checkpoint_reason": terminal["checkpoint_reason"],
        "confirmed_anchor_count": terminal["confirmed_anchor_count"],
        "local_transition_count": terminal["local_transition_count"],
        "confirmed_anchor_local_transition_ordinal": terminal[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "remote_object_count": terminal["anchor_sequence"],
        "predecessor_anchor_sha256": terminal["predecessor_anchor_sha256"],
        "current_host_head_sha256": terminal["current_host_head_sha256"],
        "current_anchor_sha256": terminal["current_anchor_sha256"],
        "current_anchor_semantic_sha256": terminal[
            "current_anchor_semantic_sha256"
        ],
        "anchor_intent_semantic_sha256": terminal[
            "current_anchor_intent_semantic_sha256"
        ],
        "candidate_remote_readback_sha256": terminal[
            "current_candidate_remote_readback_sha256"
        ],
        "receipt_semantic_sha256": terminal["current_receipt_semantic_sha256"],
        "receipt_observed_at_utc": terminal["receipt_observed_at_utc"],
        "remote_observation_sha256": _digest(f"remote-{label}"),
        "anchor_authority_sha256": _digest(f"anchor-authority{provider_suffix}"),
        "deployment_identity_sha256": _digest(f"deployment{provider_suffix}"),
        "runtime_database_identity_sha256": _digest(f"database{provider_suffix}"),
        "anchor_project_identity_sha256": _digest(f"project{provider_suffix}"),
        "source_authority_sha256": _digest(f"source-authority{provider_suffix}"),
        "signing_public_key_sha256": _digest(f"signing-key{provider_suffix}"),
        "host_identity_sha256": _digest(f"host{provider_suffix}"),
        "principal_identity_sha256": _digest(f"principal{provider_suffix}"),
        "bucket_identity_sha256": _digest(f"bucket{provider_suffix}"),
        "observation_started_monotonic_ns": started,
        "observation_completed_monotonic_ns": started + 10_000_000_000,
        "deadline_monotonic_ns": started + ADR0109_OBSERVATION_BUDGET_NS,
        "issuer_binding_sha256": _digest(f"issuer-{label}"),
        "read_only_configuration_sha256": _digest(f"configuration{provider_suffix}"),
        "semantic_sha256": _digest(f"observation-{label}"),
    }


def _proof(
    result: LifecycleV2CleanStopResult,
    *,
    label: str,
    started: int,
    issuer_identity: object,
    observation_identity: object | None = None,
    provider_suffix: str = "",
) -> LifecycleV2AuthenticatedADR0109Observation:
    primitives = LifecycleV2ADR0109ObservationPrimitives.capture(
        _observation_value(
            result,
            label=label,
            started=started,
            provider_suffix=provider_suffix,
        )
    )
    return _mint_fake_authenticated_adr0109_observation(
        primitives,
        issuer_identity=issuer_identity,
        observation_identity=(observation_identity or object()),
        capability=_FAKE_OBSERVATION_CAPABILITY,
    )


def _pre_binding_inputs() -> tuple[
    LifecycleV2Root,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopResult,
    LifecycleV2ProgressRecord,
    LifecycleV2ProgressRecord,
]:
    root = _root()
    request = _request(root)
    result = _result(root, request)
    quiescence = _quiescence(root)
    intent = _intent(
        root,
        ordinal=5,
        stage=LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
        predecessor=quiescence.sha256,
    )
    return root, request, result, quiescence, intent


def _bind_pre(
    *, challenge: bytes = b"p" * 32
) -> tuple[
    LifecycleV2Root,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopResult,
    _LifecycleV2PreEffectBindingIssuer,
    LifecycleV2AuthenticatedADR0109Observation,
    LifecycleV2PreEffectBinding,
]:
    root, request, result, quiescence, intent = _pre_binding_inputs()
    observation_issuer = object()
    issuer = _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=root,
        request=request,
        result=result,
        transport_quiescence=quiescence,
        pre_effect_intent=intent,
        observation_issuer_identity=observation_issuer,
        challenge_source=lambda size: challenge if size == 32 else b"",
    )
    observation = _proof(
        result,
        label="pre",
        started=200_000_000_000,
        issuer_identity=observation_issuer,
    )
    binding = _bind_lifecycle_v2_pre_effect_observation_once(
        issuer,
        observation=observation,
    )
    return root, request, result, issuer, observation, binding


def _prepare_post(
    *,
    challenge: bytes = b"q" * 32,
    observation_issuer: object | None = None,
) -> tuple[
    LifecycleV2Root,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopResult,
    LifecycleV2AuthenticatedADR0109Observation,
    LifecycleV2PreEffectBinding,
    LifecycleV2Transcript,
    tuple[LifecycleV2ProgressRecord, ...],
    LifecycleV2ProgressRecord,
    object,
    _LifecycleV2PostTeardownBindingIssuer,
]:
    root, request, result, _, pre_observation, pre_binding = _bind_pre()
    transcript, results = _transcript_and_results(root)
    post_intent = _intent(
        root,
        ordinal=19,
        stage=LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        predecessor=transcript.entries[-1].record_artifact_sha256,
    )
    post_observation_issuer = observation_issuer or object()
    issuer = _prepare_lifecycle_v2_post_teardown_binding_issuer(
        root=root,
        published_prefix_through_ordinal_18=transcript,
        pre_effect_binding=pre_binding,
        teardown_result_records=results,
        post_teardown_intent=post_intent,
        observation_issuer_identity=post_observation_issuer,
        challenge_source=lambda size: challenge if size == 32 else b"",
    )
    return (
        root,
        request,
        result,
        pre_observation,
        pre_binding,
        transcript,
        results,
        post_intent,
        post_observation_issuer,
        issuer,
    )


def test_pre_effect_binding_is_exact_durable_primitive_evidence_and_one_shot() -> None:
    root, request, result, issuer, _, binding = _bind_pre()
    evidence = binding.durable_evidence
    fields = evidence.to_dict()
    assert type(binding) is LifecycleV2PreEffectBinding
    assert fields["lifecycle_root_sha256"] == root.sha256
    assert fields["clean_stop_request_sha256"] == request.sha256
    assert fields["clean_stop_result_sha256"] == result.sha256
    assert fields["channel_id"] == root.channel_id
    assert fields["topology_sha256"] == root.topology_sha256
    assert fields["topology_lease_sha256"] == root.topology_lease_sha256
    assert fields["expected_checkpoint_reason"] == "clean_stop"
    assert fields["expected_clean_stop_head_sha256"] == result.terminal_projection.to_dict()[
        "current_anchor_sha256"
    ]
    assert evidence.binding_sha256 == LifecycleV2PreEffectBindingEvidence._capture(
        fields
    ).binding_sha256
    assert not any(name in fields for name in ("owner_pid", "owner_thread", "seal"))

    replay = _proof(
        result,
        label="pre-replay",
        started=220_000_000_000,
        issuer_identity=issuer._expected_observation_issuer,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        _bind_lifecycle_v2_pre_effect_observation_once(issuer, observation=replay)


def test_exact_observation_proof_cannot_be_reused_by_a_second_binding_issuer() -> None:
    root, request, result, quiescence, intent = _pre_binding_inputs()
    observation_issuer = object()
    first = _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=root,
        request=request,
        result=result,
        transport_quiescence=quiescence,
        pre_effect_intent=intent,
        observation_issuer_identity=observation_issuer,
        challenge_source=lambda _size: b"a" * 32,
    )
    second = _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=root,
        request=request,
        result=result,
        transport_quiescence=quiescence,
        pre_effect_intent=intent,
        observation_issuer_identity=observation_issuer,
        challenge_source=lambda _size: b"b" * 32,
    )
    observation = _proof(
        result,
        label="single-proof",
        started=200_000_000_000,
        issuer_identity=observation_issuer,
    )
    _bind_lifecycle_v2_pre_effect_observation_once(first, observation=observation)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="observation was replayed"):
        _bind_lifecycle_v2_pre_effect_observation_once(second, observation=observation)


def test_post_teardown_binding_covers_exact_prefix_results_volume_and_pre_binding() -> None:
    (
        root,
        _,
        result,
        _,
        pre_binding,
        transcript,
        results,
        post_intent,
        observation_issuer,
        issuer,
    ) = _prepare_post()
    observation = _proof(
        result,
        label="post",
        started=400_000_000_000,
        issuer_identity=observation_issuer,
    )
    binding = _bind_lifecycle_v2_post_teardown_observation_once(
        issuer,
        observation=observation,
    )
    fields = binding.durable_evidence.to_dict()
    assert type(binding) is LifecycleV2PostTeardownBinding
    assert fields["lifecycle_root_sha256"] == root.sha256
    assert fields["published_prefix_through_ordinal_18_sha256"] == transcript.sha256
    assert fields["pre_effect_binding_sha256"] == (
        pre_binding.durable_evidence.binding_sha256
    )
    assert fields["supervisor_stop_result_sha256"] == results[0].sha256
    assert fields["source_stop_result_sha256"] == results[1].sha256
    assert fields["supervisor_remove_result_sha256"] == results[2].sha256
    assert fields["source_remove_result_sha256"] == results[3].sha256
    assert fields["project_network_remove_result_sha256"] == results[4].sha256
    assert fields["volume_proof_sha256"] == results[5].sha256
    assert fields["post_teardown_intent_sha256"] == post_intent.sha256
    assert fields["provider_identity_sha256"] == pre_binding.durable_evidence.to_dict()[
        "provider_identity_sha256"
    ]
    assert binding.durable_evidence.binding_sha256 != (
        pre_binding.durable_evidence.binding_sha256
    )
    assert binding.durable_evidence.binding_sha256 == (
        LifecycleV2PostTeardownBindingEvidence._capture(fields).binding_sha256
    )


def test_post_teardown_rejects_reused_issuer_challenge_object_and_interval() -> None:
    _, _, result, pre_observation, pre_binding, _, _, _, _, _ = _prepare_post()
    pre_issuer_identity = pre_observation.issuer_identity
    root = _root()
    transcript, results = _transcript_and_results(root)
    post_intent = _intent(
        root,
        ordinal=19,
        stage=LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        predecessor=transcript.entries[-1].record_artifact_sha256,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="reused or crossed"):
        _prepare_lifecycle_v2_post_teardown_binding_issuer(
            root=root,
            published_prefix_through_ordinal_18=transcript,
            pre_effect_binding=pre_binding,
            teardown_result_records=results,
            post_teardown_intent=post_intent,
            observation_issuer_identity=pre_issuer_identity,
            challenge_source=lambda _size: b"q" * 32,
        )

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="challenge reused"):
        _prepare_post(challenge=b"p" * 32)

    *_, observation_issuer, issuer = _prepare_post()
    overlapping = _proof(
        result,
        label="post-overlap",
        started=205_000_000_000,
        issuer_identity=observation_issuer,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="fresh, distinct"):
        _bind_lifecycle_v2_post_teardown_observation_once(
            issuer,
            observation=overlapping,
        )


def test_post_teardown_rejects_adapted_pre_observation_and_provider_drift() -> None:
    (
        _,
        _,
        result,
        pre_observation,
        _,
        _,
        _,
        _,
        observation_issuer,
        issuer,
    ) = _prepare_post()
    adapted_identity = _proof(
        result,
        label="post-adapted",
        started=400_000_000_000,
        issuer_identity=observation_issuer,
        observation_identity=pre_observation.observation_identity,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="reused"):
        _bind_lifecycle_v2_post_teardown_observation_once(
            issuer,
            observation=adapted_identity,
        )

    *_, observation_issuer, issuer = _prepare_post()
    provider_drift = _proof(
        result,
        label="post-provider-drift",
        started=400_000_000_000,
        issuer_identity=observation_issuer,
        provider_suffix="-drift",
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="fresh, distinct"):
        _bind_lifecycle_v2_post_teardown_observation_once(
            issuer,
            observation=provider_drift,
        )


def test_cross_root_transcript_result_and_boundary_substitution_reject() -> None:
    root, request, result, quiescence, intent = _pre_binding_inputs()
    foreign = _root(suffix="root")
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="crossed"):
        _prepare_lifecycle_v2_pre_effect_binding_issuer(
            root=foreign,
            request=request,
            result=result,
            transport_quiescence=quiescence,
            pre_effect_intent=intent,
            observation_issuer_identity=object(),
            challenge_source=lambda _size: b"p" * 32,
        )

    _, _, _, _, pre_binding = _bind_pre()[1:]
    transcript, results = _transcript_and_results(root)
    post_intent = _intent(
        root,
        ordinal=19,
        stage=LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        predecessor=transcript.entries[-1].record_artifact_sha256,
    )
    bad_entries = list(transcript.entries)
    bad_entries[18] = LifecycleV2TranscriptEntry(
        ordinal=18,
        stage=LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
        record_artifact_kind="progress",
        record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
        record_artifact_sha256=_digest("substituted-volume-proof"),
        predecessor_sha256=bad_entries[17].record_artifact_sha256,
    )
    substituted = LifecycleV2Transcript(
        environment=root.environment,
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        entries=tuple(bad_entries),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="published"):
        _prepare_lifecycle_v2_post_teardown_binding_issuer(
            root=root,
            published_prefix_through_ordinal_18=substituted,
            pre_effect_binding=pre_binding,
            teardown_result_records=results,
            post_teardown_intent=post_intent,
            observation_issuer_identity=object(),
            challenge_source=lambda _size: b"q" * 32,
        )

    pre_issuer = _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=root,
        request=request,
        result=result,
        transport_quiescence=quiescence,
        pre_effect_intent=intent,
        observation_issuer_identity=object(),
        challenge_source=lambda _size: b"x" * 32,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="post-teardown seam"):
        _bind_lifecycle_v2_post_teardown_observation_once(
            pre_issuer,
            observation=object(),
        )


def test_binding_seals_reject_copy_pickle_wrong_thread_and_fork() -> None:
    _, _, result, issuer, _, binding = _bind_pre()
    for operation in (
        copy.copy,
        copy.deepcopy,
        lambda value: pickle.dumps(value),
    ):
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            operation(binding)
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            operation(issuer)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="immutable"):
        issuer._status = "prepared"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="immutable"):
        binding._evidence = binding.durable_evidence

    errors: list[BaseException] = []

    def read_binding() -> None:
        try:
            _ = binding.durable_evidence
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=read_binding)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], TrustedTimeGracefulStopV2Rejected)

    observation_issuer = object()
    fresh = _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=_pre_binding_inputs()[0],
        request=_pre_binding_inputs()[1],
        result=_pre_binding_inputs()[2],
        transport_quiescence=_pre_binding_inputs()[3],
        pre_effect_intent=_pre_binding_inputs()[4],
        observation_issuer_identity=observation_issuer,
        challenge_source=lambda _size: b"z" * 32,
    )
    fresh_proof = _proof(
        result,
        label="wrong-thread",
        started=200_000_000_000,
        issuer_identity=observation_issuer,
    )
    errors.clear()

    def consume_wrong_thread() -> None:
        try:
            _bind_lifecycle_v2_pre_effect_observation_once(fresh, observation=fresh_proof)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=consume_wrong_thread)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], TrustedTimeGracefulStopV2Rejected)

    if not hasattr(os, "fork"):
        return
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        try:
            _ = binding.durable_evidence
        except TrustedTimeGracefulStopV2Rejected:
            os.write(write_fd, b"rejected")
        else:
            os.write(write_fd, b"accepted")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    message = os.read(read_fd, 32)
    os.close(read_fd)
    waited, status = os.waitpid(child_pid, 0)
    assert waited == child_pid
    assert os.WIFEXITED(status)
    assert message == b"rejected"


def test_observation_schema_rejects_bool_integer_deadline_and_head_substitution() -> None:
    _, _, result, _, _ = _pre_binding_inputs()
    base = _observation_value(
        result,
        label="schema",
        started=200_000_000_000,
    )
    for name, replacement in (
        ("anchor_sequence", True),
        (
            "deadline_monotonic_ns",
            cast(int, base["deadline_monotonic_ns"]) - 1,
        ),
        ("candidate_remote_readback_sha256", _digest("other-anchor")),
    ):
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2ADR0109ObservationPrimitives.capture(
                {**base, name: replacement}
            )


def test_adapter_is_direct_adr0109_only_and_has_no_observation_or_effect_surface() -> None:
    path = Path("packages/adapters/trusted_time/graceful_stop_v2_reauthentication.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    source = path.read_text(encoding="utf-8")
    assert "trusted_time_post_enrollment_clean_stop_terminal_reauthentication" in source
    assert "graceful_stop_supervisor_bridge" not in source
    assert not imports.intersection({"socket", "subprocess", "docker", "requests"})
    assert (
        "prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer"
        not in source
    )
    assert "reauthenticate_clean_stop_terminal_once" not in source
    assert "publish_immutable" not in source
    assert "stop_effect_authorized" not in source
