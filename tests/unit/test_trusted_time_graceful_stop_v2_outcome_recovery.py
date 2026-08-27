from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

import pytest

from packages.domain import trusted_time_graceful_stop_v2_recovery as recovery
from packages.domain.trusted_time_graceful_stop_v2 import (
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
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_wire_file_name,
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
    RECOVERY_CLASSIFICATION_REASON_CODES,
    LifecycleV2RecoveryClassificationEnvelope,
)
from packages.persistence import trusted_time_graceful_stop_v2 as persistence
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


def _root() -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment="test",
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
            "payload_contract_version": (
                "phase6d-trusted-time-head-anchor-clean-stop-result-v2"
            ),
            "key_generation": root.transport_key_generation,
            "signing_key_id": root.supervisor_transport_key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(
                root, intent
            ),
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
        "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(
            root, intent
        ),
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
                "envelope_contract_version": (
                    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION
                ),
                "frame_type": "clean_stop_result",
                "payload_contract_version": (
                    "phase6d-trusted-time-head-anchor-clean-stop-result-v2"
                ),
                "clean_stop_result_payload_sha256": hashlib.sha256(
                    envelope.payload
                ).hexdigest(),
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
    return FakeLifecycleV2Transport(envelope).exchange(request, request_envelope)


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
        return {
            **_result_evidence(root, ordinal),
            "observation_semantic_sha256": _digest(f"observation-{ordinal}"),
            "binding_semantic_sha256": _digest(f"binding-{ordinal}"),
            "observed_head_sha256": _digest(f"head-{ordinal}"),
            "provider_identity_sha256": _digest("provider"),
        }
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
            "docker_post_inspect_request_semantic_sha256": _digest(
                f"inspect-{ordinal}"
            ),
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
            "docker_post_inspect_request_semantic_sha256": _digest(
                f"inspect-{ordinal - 1}"
            ),
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
            "state_volume_identity_sha256": (
                root.chrony_state_volume_identity_sha256
            ),
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


def _repository(
    store: FakeLifecycleV2ArtifactStore,
) -> Any:
    return persistence._open_injected_lifecycle_v2_repository(
        store,
        artifact_directory_path=ARTIFACT_DIRECTORY,
        retained_wire_verifier=FakeLifecycleV2RetainedWireVerifier(),
    )


def _complete_success_prefix(
    store: FakeLifecycleV2ArtifactStore,
) -> tuple[Any, LifecycleV2Root]:
    root = _root()
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    intent = _request_intent(root, basis)
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    envelope = _terminal_envelope(root, intent)
    terminal = _terminal_record(root, intent, envelope, store)
    repository.retain_authenticated_terminal_wire(
        terminal,
        _fake_authenticated_terminal(root, basis, intent, envelope),
    )
    predecessor = terminal
    for ordinal in range(3, 23):
        record = _record(root, predecessor, ordinal)
        if ordinal == 3:
            repository.retain_transport_cleanup_commitment(record)
        elif ordinal == 4:
            repository.retain_transport_quiescence(record)
        elif ordinal in {5, 19}:
            repository.retain_reauthentication_intent(record)
        elif ordinal in {6, 20}:
            repository.retain_reauthentication_result(record)
        elif ordinal in {7, 9, 11, 13, 15, 17}:
            repository.retain_effect_intent(record)
        elif ordinal in {8, 10, 12, 14, 16, 18}:
            repository.retain_effect_result(record)
        elif ordinal == 21:
            repository.retain_terminal_cleanup_intent(record)
        else:
            repository.retain_terminal_cleanup_result(record)
        predecessor = record
    repository.publish_transcript()
    return repository, root


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
            "transport_authority_manifest_sha256": (
                root.transport_authority_manifest_sha256
            ),
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
    return recovery._mint_fake_authenticated_lifecycle_v2_recovery_intent(
        envelope=_recovery_envelope(root, transcript, reason=reason),
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
        capability=recovery._FAKE_RECOVERY_INTENT_CAPABILITY,
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
        if (
            type(result) is not _Disposition
            or result.capability is not _DISPOSITION_CAPABILITY
        ):
            raise ValueError("disposition is not sealed")
        return result


class _TraceStore(FakeLifecycleV2ArtifactStore):
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
        assert (
            reopened.status
            is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
        )
    commit = reopened.finalize_retained_outcome_commit()
    assert commit.to_dict()["outcome_status"] == "recovery_required"


def test_confirmed_success_orders_readback_disposal_final_sample_then_marker() -> None:
    events: list[str] = []
    store = _TraceStore(events)
    repository, root = _complete_success_prefix(store)
    protocol_start = root.operation_deadline_boottime_ns - 2

    outcome, commit = repository.commit_confirmed_success(
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
    store = FakeLifecycleV2ArtifactStore()
    repository, root = _complete_success_prefix(store)
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
    store = FakeLifecycleV2ArtifactStore()
    repository, root = _complete_success_prefix(store)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="final CLOCK_BOOTTIME",
    ):
        repository.commit_confirmed_success(
            clock=_Clock(
                [root.admission_started_boottime_ns + 100, final_sample]
            ),
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
    store = FakeLifecycleV2ArtifactStore()
    repository, root = _complete_success_prefix(store)
    disposer = _Disposer(
        descriptor_count=1 if field == "descriptor" else 0,
        registry_count=1 if field == "registry" else 0,
    )

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed, match="not empty"):
        repository.commit_confirmed_success(
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
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="commit", phase=phase)
    )
    repository, root = _complete_success_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_confirmed_success(
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
    store = FakeLifecycleV2ArtifactStore(
        fault=FakePublicationFault(operation="outcome", phase=phase)
    )
    repository, root = _complete_success_prefix(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.commit_confirmed_success(
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
