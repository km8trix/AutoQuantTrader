from __future__ import annotations

import ast
import base64
import hashlib
import os
import threading
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as topology_reader
from packages.application import trusted_time_graceful_stop_v2_admission as v2_admission
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
    LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
    LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
    LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
    LIFECYCLE_V2_SERVICE,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_SERVICE,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2Outcome,
    LifecycleV2OutcomeCommit,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    decode_unverified_lifecycle_v2_transport_envelope,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_non_authority_facts,
    lifecycle_v2_progress_file_name,
    lifecycle_v2_wire_file_name,
)
from packages.persistence import trusted_time_graceful_stop_v2 as persistence
from scripts import trusted_time_post_enrollment_graceful_stop_decision_artifacts as artifacts
from scripts import verify_trusted_time_images as image_verifier
from scripts.trusted_time_post_enrollment_graceful_stop_lifecycle import (
    TrustedTimePostEnrollmentGracefulStopLifecycleRejected,
    decode_post_enrollment_graceful_stop_attempt_bytes,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_execution_admission as execution_fx
from tests.unit import (
    test_trusted_time_post_enrollment_graceful_stop_decision_artifacts as decision_fx,
)
from tests.unit import trusted_time_graceful_stop_v2_fakes as v2_fakes
from tests.unit.trusted_time_graceful_stop_v2_fakes import (
    FakeLifecycleV2ArtifactStore,
    FakeLifecycleV2DockerEffects,
    FakeLifecycleV2Fault,
    FakeLifecycleV2RetainedWireVerifier,
    FakeLifecycleV2Transport,
    FakePublicationFault,
    fake_adapters_non_authority_facts,
)

ROOT = Path(__file__).resolve().parents[2]
OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"
ARTIFACT_DIRECTORY = "/injected/adr0121/trusted-time"
UTC_TEXT = "2026-08-26T12:00:00.000000Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _root() -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment="test",
        graceful_stop_operation_id=OPERATION_ID,
        graceful_stop_target_sha256=_digest("target"),
        graceful_stop_decision_v1_sha256=_digest("decision"),
        graceful_stop_operator_attestation_envelope_sha256=_digest("attestation"),
        historical_decision_receipt_sha256=_digest("historical-receipt"),
        admission_sha256=_digest("admission"),
        topology_sha256=_digest("topology"),
        topology_lease_sha256=_digest("topology-lease"),
        trusted_head_sha256=_digest("trusted-head"),
        stop_authority_sha256=_digest("stop-authority"),
        transport_authority_manifest_sha256=_digest("transport-authority"),
        transport_key_generation=1,
        host_transport_key_id="host-key-1",
        supervisor_transport_key_id="supervisor-key-1",
        boot_epoch_sha256=_digest("boot"),
        host_process_epoch_sha256=_digest("host-process"),
        supervisor_process_epoch_sha256=_digest("supervisor-process"),
        channel_id=_digest("channel"),
        supervisor_container_id=_digest("supervisor-container"),
        source_container_id=_digest("source-container"),
        project_network_id=_digest("network"),
        chrony_command_socket_volume_identity_sha256=_digest("command-volume"),
        chrony_state_volume_identity_sha256=_digest("state-volume"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _request_basis(root: LifecycleV2Root) -> LifecycleV2CleanStopRequestBasis:
    return LifecycleV2CleanStopRequestBasis.from_root(root)


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


def _final_request(
    root: LifecycleV2Root,
    basis: LifecycleV2CleanStopRequestBasis,
    intent: LifecycleV2ProgressRecord,
) -> LifecycleV2CleanStopRequest:
    return LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)


def _envelope(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
    *,
    frame_type: str,
    payload: bytes,
) -> UnverifiedLifecycleV2TransportEnvelope:
    rules = {
        "clean_stop_request": (
            "host_to_supervisor",
            2,
            LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
            "host-key-1",
        ),
        "clean_stop_result": (
            "supervisor_to_host",
            1,
            "phase6d-trusted-time-head-anchor-clean-stop-result-v2",
            "supervisor-key-1",
        ),
        "clean_stop_error": (
            "supervisor_to_host",
            1,
            "phase6d-trusted-time-head-anchor-clean-stop-error-v2",
            "supervisor-key-1",
        ),
    }
    direction, counter, payload_contract, key_id = rules[frame_type]
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_TRANSPORT_SERVICE,
            "protocol_version": 2,
            "environment": root.environment,
            "direction": direction,
            "frame_type": frame_type,
            "payload_contract_version": payload_contract,
            "key_generation": root.transport_key_generation,
            "signing_key_id": key_id,
            "boot_epoch_sha256": root.boot_epoch_sha256,
            "host_process_epoch_sha256": root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": root.supervisor_process_epoch_sha256,
            "channel_id": root.channel_id,
            "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(root, intent),
            "message_counter": counter,
            "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _result_envelope(
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
    return _envelope(root, intent, frame_type="clean_stop_result", payload=payload)


def _result_record(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> LifecycleV2ProgressRecord:
    file_name = lifecycle_v2_wire_file_name(envelope)
    fake_store = FakeLifecycleV2ArtifactStore()
    store_identity = fake_store.identity
    publication = fake_store.preview_publication_receipt(file_name, envelope.encoded)
    publication_receipt = {
        "contract_version": (
            "phase6d-post-enrollment-graceful-stop-wire-envelope-publication-receipt-v2"
        ),
        "service": LIFECYCLE_V2_SERVICE,
        "status": "wire_envelope_published",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "artifact_kind": "signed_result_envelope",
        "artifact_directory_path": store_identity.artifact_directory_path,
        "artifact_directory_device": store_identity.directory_device,
        "artifact_directory_inode": store_identity.directory_inode,
        "artifact_path": f"{store_identity.artifact_directory_path}/{file_name}",
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
        "publication_authorized_boottime_ns": root.admission_started_boottime_ns + 1,
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
                "key_generation": 1,
                "signing_key_id": "supervisor-key-1",
                "channel_id": root.channel_id,
                "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(
                    root, intent
                ),
                "message_counter": 1,
                "deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
                "wire_publication_receipt": publication_receipt,
                "wire_publication_receipt_sha256": _digest("wire-receipt"),
                "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
                "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )


def _fake_authenticated_result(
    root: LifecycleV2Root,
    basis: LifecycleV2CleanStopRequestBasis,
    intent: LifecycleV2ProgressRecord,
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> Any:
    request = _final_request(root, basis, intent)
    request_envelope = _envelope(
        root, intent, frame_type="clean_stop_request", payload=request.encoded
    )
    return FakeLifecycleV2Transport(envelope).exchange(request, request_envelope)


def _repository(
    store: FakeLifecycleV2ArtifactStore | None = None,
    verifier: persistence.LifecycleV2RetainedWireVerifier | None = None,
) -> Any:
    return persistence._open_injected_lifecycle_v2_repository(
        store or FakeLifecycleV2ArtifactStore(),
        artifact_directory_path=ARTIFACT_DIRECTORY,
        retained_wire_verifier=verifier,
    )


class _NamespaceRaceArtifactStore(FakeLifecycleV2ArtifactStore):
    def __init__(
        self,
        *,
        initial: dict[str, bytes],
        racing_name: str,
    ) -> None:
        super().__init__(initial=initial)
        self.racing_name = racing_name
        self.race_injected = False

    def read_stable(self, file_name: str) -> persistence.LifecycleV2ArtifactReadback:
        readback = super().read_stable(file_name)
        if not self.race_injected:
            self.race_injected = True
            self.inject(self.racing_name, b"racing-namespace-entry\n")
        return readback


class _CountingCloseArtifactStore(FakeLifecycleV2ArtifactStore):
    __slots__ = ("close_calls",)

    def __init__(self, *, inventory_failure_call: int) -> None:
        super().__init__(inventory_failure_call=inventory_failure_call)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


class _WireReceiptInodeMismatchArtifactStore(FakeLifecycleV2ArtifactStore):
    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> persistence.LifecycleV2ArtifactPublicationReceipt:
        receipt = super().publish_immutable(
            staging_name=staging_name,
            final_name=final_name,
            encoded=encoded,
        )
        if "-wire-" in final_name:
            return replace(receipt, final_inode=receipt.final_inode + 1)
        return receipt


class _MissingNoReplaceReceiptArtifactStore(FakeLifecycleV2ArtifactStore):
    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> persistence.LifecycleV2ArtifactPublicationReceipt:
        receipt = super().publish_immutable(
            staging_name=staging_name,
            final_name=final_name,
            encoded=encoded,
        )
        if "-record-" in final_name:
            return replace(receipt, no_replace_rename_completed=False)
        return receipt


def _tamper_wire_publication_receipt(
    record: LifecycleV2ProgressRecord,
    *,
    field_name: str,
    replacement: object,
) -> LifecycleV2ProgressRecord:
    evidence = record.evidence.to_dict()
    receipt = cast(dict[str, object], evidence["wire_publication_receipt"])
    evidence["wire_publication_receipt"] = {**receipt, field_name: replacement}
    return replace(record, evidence=FrozenJsonObject.capture(evidence))


def _recovery_intent(
    root: LifecycleV2Root,
    predecessor: LifecycleV2ProgressRecord,
    classified_transcript_sha256: str,
) -> LifecycleV2ProgressRecord:
    return LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=predecessor.ordinal + 1,
        stage=LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        predecessor_sha256=predecessor.sha256,
        effect_kind="recovery_classification",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "recovery_classification_envelope_sha256": _digest("recovery-envelope"),
                "operator_nonce_sha256": _digest("recovery-nonce"),
                "recovery_key_id": "recovery-key-1",
                "transport_authority_manifest_sha256": (root.transport_authority_manifest_sha256),
                "classified_transcript_sha256": classified_transcript_sha256,
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
                "reason_code": "call_or_result_ambiguous",
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )


def _recovery_outcome_pair(
    root: LifecycleV2Root,
    recovery_intent: LifecycleV2ProgressRecord,
    transcript_sha256: str,
    *,
    overrides: dict[str, object] | None = None,
) -> tuple[LifecycleV2Outcome, LifecycleV2OutcomeCommit]:
    protocol_start = root.admission_started_boottime_ns + 10
    outcome_fields: dict[str, object] = {
        "contract_version": LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
        "service": LIFECYCLE_V2_SERVICE,
        "status": "recovery_required",
        "lifecycle_version": 2,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "ordinal": recovery_intent.ordinal + 1,
        "predecessor_sha256": recovery_intent.sha256,
        "final_stage": recovery_intent.stage.value,
        "transcript_sha256": transcript_sha256,
        "reason_code": "call_or_result_ambiguous",
        "pre_effect_binding_sha256": None,
        "post_teardown_binding_sha256": None,
        "volume_proof_sha256": None,
        "terminal_cleanup_sha256": None,
        "stop_effects_confirmed": False,
        "teardown_confirmed": False,
        "terminal_cleanup_confirmed": False,
        "admission_started_boottime_ns": root.admission_started_boottime_ns,
        "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        "commit_protocol_started_boottime_ns": protocol_start,
        "commit_publication_authorization_deadline_boottime_ns": (protocol_start + 5_000_000_000),
        "commit_authorized_boottime_ns": protocol_start + 1,
        "created_at_utc": UTC_TEXT,
    }
    outcome_fields.update(overrides or {})
    outcome = LifecycleV2Outcome.capture(outcome_fields)
    exact = outcome.to_dict()
    commit = LifecycleV2OutcomeCommit.capture(
        {
            "contract_version": LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "terminal_outcome_committed",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": exact["graceful_stop_operation_id"],
            "root_sha256": exact["root_sha256"],
            "outcome_sha256": outcome.sha256,
            "outcome_status": outcome.status,
            "transcript_sha256": exact["transcript_sha256"],
            "admission_started_boottime_ns": exact["admission_started_boottime_ns"],
            "commit_protocol_started_boottime_ns": exact["commit_protocol_started_boottime_ns"],
            "commit_publication_authorization_deadline_boottime_ns": exact[
                "commit_publication_authorization_deadline_boottime_ns"
            ],
            "commit_authorized_boottime_ns": exact["commit_authorized_boottime_ns"],
            "operation_deadline_boottime_ns": exact["operation_deadline_boottime_ns"],
            "committed_at_utc": UTC_TEXT,
        },
        outcome=outcome,
    )
    return outcome, commit


def test_root_request_record_and_transcript_codecs_are_canonical() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    request = _final_request(root, basis, intent)

    assert decode_lifecycle_v2_root(root.encoded) == root
    assert decode_lifecycle_v2_progress_record(intent.encoded) == intent
    assert request.to_dict()["request_basis_sha256"] == basis.sha256
    assert request.to_dict()["request_intent_sha256"] == intent.sha256
    assert request.encoded.endswith(b"\n")

    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    transcript = repository.publish_transcript()
    assert decode_lifecycle_v2_transcript(transcript.encoded) == transcript
    assert [entry.ordinal for entry in transcript.entries] == [0, 1]
    assert transcript.entries[1].predecessor_sha256 == root.sha256


@pytest.mark.parametrize(
    ("value_type", "arguments"),
    [
        (FrozenJsonObject, ((("caller_selected", True),),)),
        (LifecycleV2CleanStopRequestBasis, (FrozenJsonObject.capture({}),)),
        (LifecycleV2CleanStopRequest, (FrozenJsonObject.capture({}),)),
        (
            UnverifiedLifecycleV2TransportEnvelope,
            (FrozenJsonObject.capture({}), b"payload", b"signature"),
        ),
        (LifecycleV2Outcome, (FrozenJsonObject.capture({}),)),
        (LifecycleV2OutcomeCommit, (FrozenJsonObject.capture({}),)),
    ],
)
def test_canonical_value_public_initializers_are_sealed(
    value_type: type[object],
    arguments: tuple[object, ...],
) -> None:
    with pytest.raises(TypeError):
        cast(Any, value_type)(*arguments)


def test_frozen_json_rejects_normal_mutation_and_forged_internal_entries() -> None:
    evidence = FrozenJsonObject.capture({"value": "original"})

    with pytest.raises(FrozenInstanceError):
        cast(Any, evidence).entries = (("value", "mutated"),)

    object.__setattr__(
        evidence,
        "entries",
        (("value", "original"), ("value", "forged")),
    )
    with pytest.raises(
        TrustedTimeGracefulStopV2Rejected,
        match="not canonically represented",
    ):
        evidence.to_dict()


def test_request_intent_and_final_request_are_derived_from_one_exact_root_basis() -> None:
    root = _root()
    other_root = replace(root, channel_id=_digest("other-channel"))
    wrong_basis = _request_basis(other_root)
    caller_selected_intent = _request_intent(root, wrong_basis)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="root/basis-derived",
    ):
        repository.retain_request_intent(caller_selected_intent, wrong_basis)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="exact root/basis/intent"):
        LifecycleV2CleanStopRequest.from_prefix(root, wrong_basis, caller_selected_intent)
    assert store.inventory().names == (LIFECYCLE_ROOT_FILE_NAME,)

    store.inject(
        lifecycle_v2_progress_file_name(caller_selected_intent),
        caller_selected_intent.encoded,
    )
    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="namespace cannot be authenticated",
    ):
        _repository(store)


def test_repository_redecodes_forged_exact_type_root_and_progress_values() -> None:
    root = _root()
    forged_root = object.__new__(LifecycleV2Root)
    for field_definition in dataclass_fields(root):
        object.__setattr__(
            forged_root,
            field_definition.name,
            getattr(root, field_definition.name),
        )
    object.__setattr__(
        forged_root,
        "operation_deadline_boottime_ns",
        root.admission_started_boottime_ns + 1,
    )
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="root is not canonically valid",
    ):
        _repository().reserve_root(forged_root)

    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    forged_intent = object.__new__(LifecycleV2ProgressRecord)
    for field_definition in dataclass_fields(intent):
        object.__setattr__(
            forged_intent,
            field_definition.name,
            getattr(intent, field_definition.name),
        )
    object.__setattr__(forged_intent, "ordinal", True)
    repository = _repository()
    repository.reserve_root(root)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="progress record is not canonically valid",
    ):
        repository.retain_request_intent(forged_intent, basis)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda encoded: encoded[:-1],
        lambda encoded: encoded.replace(b"{", b"{ ", 1),
        lambda encoded: encoded.replace(b'"ordinal":0', b'"ordinal":false'),
        lambda encoded: encoded.replace(b'"service":', b'"service":"duplicate","service":', 1),
    ],
)
def test_canonical_decoder_rejects_truncation_whitespace_bool_integer_and_duplicates(
    mutation: Any,
) -> None:
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        decode_lifecycle_v2_root(mutation(_root().encoded))


def test_canonical_decoder_normalizes_excessive_integer_text_to_domain_error() -> None:
    encoded = b'{"value":' + (b"9" * 5_000) + b"}\n"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="integer"):
        decode_canonical_v2_json_object(encoded, maximum_bytes=64 * 1_024)


def test_canonical_decoder_normalizes_deep_json_recursion_to_domain_error() -> None:
    encoded = b'{"value":' + (b"[" * 30_000) + b"0" + (b"]" * 30_000) + b"}\n"
    assert len(encoded) <= 64 * 1_024

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="invalid JSON"):
        decode_canonical_v2_json_object(encoded, maximum_bytes=64 * 1_024)


@pytest.mark.parametrize(
    ("summary_name", "replacement"), [("last_ordinal", False), ("entry_count", True)]
)
def test_transcript_summary_rejects_boolean_integer_aliases(
    summary_name: str,
    replacement: bool,
) -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(_root())
    fields = repository.publish_transcript().to_dict()
    fields[summary_name] = replacement
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=summary_name):
        decode_lifecycle_v2_transcript(canonical_v2_json_bytes(fields, maximum_bytes=256 * 1_024))


def test_unhashable_discriminators_and_boolean_message_counter_are_domain_errors() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope_fields = _result_envelope(root, intent).to_dict()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="discriminator"):
        UnverifiedLifecycleV2TransportEnvelope.capture({**envelope_fields, "frame_type": []})
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="message_counter"):
        UnverifiedLifecycleV2TransportEnvelope.capture({**envelope_fields, "message_counter": True})

    recovery = _recovery_intent(root, intent, _digest("classified-transcript"))
    outcome, commit = _recovery_outcome_pair(root, recovery, _digest("final-transcript"))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="discriminator"):
        LifecycleV2Outcome.capture({**outcome.to_dict(), "status": []})
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="discriminator"):
        LifecycleV2OutcomeCommit.capture({**commit.to_dict(), "outcome_status": []})


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("key_generation", True),
        ("key_generation", 0),
        ("message_counter", True),
        ("message_counter", 2),
    ],
)
def test_ordinal_two_evidence_requires_exact_integer_generation_and_counter(
    field_name: str,
    replacement: object,
) -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    record = _result_record(root, intent, _result_envelope(root, intent))
    evidence = cast(dict[str, object], record.to_dict()["evidence"])
    evidence[field_name] = replacement

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=field_name):
        replace(record, evidence=FrozenJsonObject.capture(evidence))


def test_volume_delete_count_rejects_boolean_zero_alias() -> None:
    root = _root()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="volume_delete_call_count"):
        LifecycleV2ProgressRecord(
            graceful_stop_operation_id=root.graceful_stop_operation_id,
            root_sha256=root.sha256,
            ordinal=18,
            stage=LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
            predecessor_sha256=_digest("ordinal-17"),
            effect_kind="volume_preservation",
            deadline_boottime_ns=root.operation_deadline_boottime_ns,
            evidence=FrozenJsonObject.capture(
                {
                    "intent_sha256": _digest("volume-intent"),
                    "responder_identity_sha256": _digest("daemon"),
                    "disposition": "confirmed",
                    "result_semantic_sha256": _digest("result"),
                    "call_started_boottime_ns": root.admission_started_boottime_ns + 1,
                    "call_completed_boottime_ns": root.admission_started_boottime_ns + 2,
                    "command_socket_volume_identity_sha256": _digest("command-volume"),
                    "state_volume_identity_sha256": _digest("state-volume"),
                    "docker_api_trace_sha256": _digest("trace"),
                    "volume_delete_call_count": False,
                    "docker_request_semantic_sha256_list": [_digest("request")],
                    "result_semantic": {"confirmed": True},
                    "docker_method_trace_entry_sha256_list": [_digest("entry")],
                }
            ),
            recorded_at_utc=UTC_TEXT,
        )


def test_operation_deadline_equality_overflow_and_drift_fail_closed() -> None:
    root_fields = _root().to_dict()
    kwargs = {
        name: value
        for name, value in root_fields.items()
        if name
        not in {"contract_version", "service", "status", "lifecycle_version", "phase", "ordinal"}
    }
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="checked sum"):
        LifecycleV2Root(**cast(Any, {**kwargs, "operation_deadline_boottime_ns": 9}))
    maximum_start = 2**63 - 1 - 600_000_000_000
    exact = LifecycleV2Root(
        **cast(
            Any,
            {
                **kwargs,
                "admission_started_boottime_ns": maximum_start,
                "clean_stop_result_deadline_boottime_ns": maximum_start + 1,
                "operation_deadline_boottime_ns": 2**63 - 1,
            },
        )
    )
    assert exact.operation_deadline_boottime_ns == 2**63 - 1
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="overflows"):
        LifecycleV2Root(
            **cast(
                Any,
                {
                    **kwargs,
                    "admission_started_boottime_ns": maximum_start + 1,
                    "clean_stop_result_deadline_boottime_ns": maximum_start + 2,
                    "operation_deadline_boottime_ns": 2**63 - 1,
                },
            )
        )


def test_v1_and_v2_root_codecs_reject_each_others_bytes() -> None:
    root = _root()
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        decode_post_enrollment_graceful_stop_attempt_bytes(root.encoded)
    v1 = canonical_v2_json_bytes(
        {"contract_version": "phase6d-post-enrollment-graceful-stop-attempt-v1"},
        maximum_bytes=1_024,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        decode_lifecycle_v2_root(v1)


def test_shared_root_rejects_v1_unknown_and_orphan_names_without_cleanup() -> None:
    v1 = canonical_v2_json_bytes(
        {"contract_version": "phase6d-post-enrollment-graceful-stop-attempt-v1"},
        maximum_bytes=1_024,
    )
    with pytest.raises(persistence.LifecycleV2SlotConsumed):
        _repository(FakeLifecycleV2ArtifactStore(initial={LIFECYCLE_ROOT_FILE_NAME: v1}))
    unknown = canonical_v2_json_bytes(
        {"contract_version": "phase6d-future-root-v99"}, maximum_bytes=1_024
    )
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(FakeLifecycleV2ArtifactStore(initial={LIFECYCLE_ROOT_FILE_NAME: unknown}))
    orphan = FakeLifecycleV2ArtifactStore(initial={"unknown.json": b"{}\n"})
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(orphan)
    assert orphan.inventory().names == ("unknown.json",)


def test_repository_derives_canonical_store_identity_and_rejects_duplicate_path_drift() -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository = persistence._open_injected_lifecycle_v2_repository(store)
    assert repository.artifact_store_identity == store.identity
    with pytest.raises(FrozenInstanceError):
        cast(Any, repository.artifact_store_identity).directory_inode = 999
    repository.close()
    assert store.close_count == 1

    mismatched = FakeLifecycleV2ArtifactStore()
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="duplicates the store identity incorrectly",
    ):
        persistence._open_injected_lifecycle_v2_repository(
            mismatched,
            artifact_directory_path="/different/injected/trusted-time",
        )
    assert mismatched.close_count == 1


def test_repository_context_close_is_origin_bound_and_idempotent() -> None:
    store = FakeLifecycleV2ArtifactStore()
    with _repository(store) as repository:
        assert repository.status is persistence.LifecycleV2RepositoryStatus.UNRESERVED
    assert store.close_count == 1
    repository.close()
    assert store.close_count == 1
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed, match="closed"):
        _ = repository.status


def test_repository_burn_and_context_exit_invoke_store_disposal_only_once() -> None:
    store = _CountingCloseArtifactStore(inventory_failure_call=3)
    repository: Any
    with (
        pytest.raises(persistence.LifecycleV2RetentionUnconfirmed),
        _repository(store) as repository,
    ):
        repository.reserve_root(_root())

    assert store.close_calls == 1
    repository.close()
    assert store.close_calls == 1
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed, match="closed"):
        _ = repository.status


def test_repository_status_and_close_reject_wrong_thread_before_any_disposal() -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    failures: list[BaseException] = []

    def wrong_thread() -> None:
        for operation in (lambda: repository.status, repository.close):
            try:
                operation()
            except BaseException as error:
                failures.append(error)

    thread = threading.Thread(target=wrong_thread)
    thread.start()
    thread.join()
    assert len(failures) == 2
    assert all(isinstance(error, persistence.LifecycleV2RetentionUnconfirmed) for error in failures)
    assert store.close_count == 0
    assert repository.status is persistence.LifecycleV2RepositoryStatus.UNRESERVED
    repository.close()
    assert store.close_count == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="repository fork guard is POSIX-only")
def test_repository_status_and_disposal_are_invalid_in_a_real_fork_child() -> None:
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    read_pipe, write_pipe = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_pipe)
        rejected = 0
        for operation in (lambda: repository.status, repository.close):
            try:
                operation()
            except persistence.LifecycleV2RetentionUnconfirmed:
                rejected += 1
        os.write(write_pipe, str(rejected).encode("ascii"))
        os.close(write_pipe)
        os._exit(0 if rejected == 2 else 93)

    os.close(write_pipe)
    child_report = os.read(read_pipe, 1)
    os.close(read_pipe)
    waited_pid, wait_status = os.waitpid(child_pid, 0)
    try:
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
        assert child_report == b"2"
        assert repository.status is persistence.LifecycleV2RepositoryStatus.UNRESERVED
        assert store.close_count == 0
    finally:
        repository.close()
    assert store.close_count == 1


@pytest.mark.parametrize("fault", ["inventory", "identity_path"])
def test_root_reservation_inventory_and_path_faults_poison_and_dispose(fault: str) -> None:
    store = FakeLifecycleV2ArtifactStore(inventory_failure_call=3 if fault == "inventory" else None)
    repository = _repository(store)
    if fault == "identity_path":
        store.replace_identity_for_test(
            replace(
                store.identity,
                artifact_directory_path="/replaced/injected/trusted-time",
            )
        )

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.reserve_root(_root())

    assert store.close_count == 1
    if fault == "identity_path":
        with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed, match="identity changed"):
            _ = repository.status
    else:
        assert repository.status is persistence.LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED


@pytest.mark.parametrize("phase", ["before", "renamed", "directory_fsynced", "readback"])
def test_root_faults_burn_repository_and_never_reopen_normal_attempt(phase: str) -> None:
    store = FakeLifecycleV2ArtifactStore(fault=FakePublicationFault("root", phase))
    repository = _repository(store)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.reserve_root(_root())
    assert repository.status is persistence.LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.reserve_root(_root())


@pytest.mark.parametrize(
    "phase", ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced"]
)
def test_progress_store_faults_are_retention_unconfirmed(phase: str) -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    store = FakeLifecycleV2ArtifactStore(fault=FakePublicationFault("record", phase))
    repository = _repository(store)
    repository.reserve_root(root)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.retain_request_intent(intent, _request_basis(root))
    assert repository.status is persistence.LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED
    if phase in {"staging_created", "file_fsynced"}:
        assert ".post-enrollment-graceful-stop-v2-record-staging" in store.inventory().names


def test_order_replay_and_cross_root_substitution_are_rejected_before_store() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    repository = _repository()
    repository.reserve_root(root)
    wrong_stage = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=1,
        stage=LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
        predecessor_sha256=root.sha256,
        effect_kind="transport_cleanup",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "clean_stop_result_sha256": _digest("result"),
                "supervisor_cleanup_commitment_sha256": _digest("commitment"),
                "channel_id": root.channel_id,
                "host_process_epoch_sha256": root.host_process_epoch_sha256,
                "host_socket_identity_sha256": _digest("socket"),
                "host_peer_credential_sha256": _digest("peer"),
                "host_raw_key_path": "/fake/key",
                "host_raw_key_device": 1,
                "host_raw_key_inode": 2,
                "host_challenge_sha256": _digest("challenge"),
                "host_process_nonce_sha256": _digest("nonce"),
                "cleanup_deadline_boottime_ns": root.clean_stop_result_deadline_boottime_ns,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )
    with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="out of order"):
        repository.retain_transport_cleanup_commitment(wrong_stage)
    repository.retain_request_intent(intent, basis)
    with pytest.raises(persistence.LifecycleV2RepositoryRejected, match=r"does not bind|ordinal"):
        repository.retain_request_intent(intent, basis)


def test_terminal_wire_is_full_envelope_named_by_full_envelope_digest() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    authenticated = _fake_authenticated_result(root, basis, intent, envelope)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    repository.retain_authenticated_terminal_wire(record, authenticated)
    wire_name = lifecycle_v2_wire_file_name(envelope)
    assert store.read_stable(wire_name).encoded == envelope.encoded
    assert hashlib.sha256(store.read_stable(wire_name).encoded).hexdigest() == envelope.sha256
    transcript = repository.publish_transcript()
    assert transcript.entries[2].wire_artifact_file_name == wire_name
    assert transcript.entries[2].wire_artifact_sha256 == envelope.sha256


def test_structurally_valid_unverified_wire_cannot_cross_repository_boundary() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    inventory_before = store.inventory()

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="fake-authenticated signed wire bytes",
    ):
        repository.retain_authenticated_terminal_wire(record, cast(Any, envelope))

    assert store.inventory() == inventory_before
    assert repository.status is persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED


def test_restart_with_retained_wire_fails_closed_until_crypto_reauth_exists() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    authenticated = _fake_authenticated_result(root, basis, intent, envelope)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    repository.retain_authenticated_terminal_wire(record, authenticated)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="cannot reauthenticate retained wire signatures",
    ):
        _repository(store)


def test_restart_with_retained_wire_uses_only_the_injected_verifier_seam() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    repository.retain_authenticated_terminal_wire(
        record,
        _fake_authenticated_result(root, basis, intent, envelope),
    )

    verifier = FakeLifecycleV2RetainedWireVerifier()
    reopened = _repository(store, verifier)

    assert reopened.status is persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED
    assert verifier.calls == [(envelope, root, intent, record, ARTIFACT_DIRECTORY)]


@pytest.mark.parametrize(
    "fault",
    [
        "reject",
        "invalid_return",
        "invalid_capability",
        "substitute_on_require",
        "wrong_manifest",
        "wrong_signer",
    ],
)
def test_retained_wire_verifier_rejection_or_tamper_never_authenticates_restart(
    fault: str,
) -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    repository.retain_authenticated_terminal_wire(
        record,
        _fake_authenticated_result(root, basis, intent, envelope),
    )
    verifier = FakeLifecycleV2RetainedWireVerifier(**{fault: True})

    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        _repository(store, verifier)


@pytest.mark.parametrize(
    "racing_name",
    [
        ".post-enrollment-graceful-stop-v2-wire-result-staging",
        "trusted-time-post-enrollment-graceful-stop-v2-wire-error-" + "b" * 64 + ".json",
        "trusted-time-post-enrollment-graceful-stop-v2-outcome-" + "c" * 64 + ".json",
        "unknown-racing-artifact.json",
        LIFECYCLE_ROOT_FILE_NAME,
    ],
)
def test_complete_namespace_load_rejects_every_post_snapshot_race(
    racing_name: str,
) -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _result_record(root, intent, envelope)
    store = _NamespaceRaceArtifactStore(
        initial={
            LIFECYCLE_ROOT_FILE_NAME: root.encoded,
            lifecycle_v2_progress_file_name(intent): intent.encoded,
            lifecycle_v2_progress_file_name(record): record.encoded,
            lifecycle_v2_wire_file_name(envelope): envelope.encoded,
        },
        racing_name=racing_name,
    )

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="changed during complete stable load",
    ):
        _repository(store, FakeLifecycleV2RetainedWireVerifier())

    assert store.race_injected is True
    assert store.close_count == 1


@pytest.mark.parametrize("load_phase", ["live", "restart"])
@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("artifact_directory_path", "/wrong/trusted-time"),
        ("file_inode", 999),
        ("directory_fsync_completed", False),
    ],
)
def test_ordinal_two_binds_live_and_restart_to_the_exact_physical_receipt(
    load_phase: str,
    field_name: str,
    replacement: object,
) -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _tamper_wire_publication_receipt(
        _result_record(root, intent, envelope),
        field_name=field_name,
        replacement=replacement,
    )
    store = FakeLifecycleV2ArtifactStore()
    if load_phase == "live":
        repository = _repository(store)
        repository.reserve_root(root)
        repository.retain_request_intent(intent, basis)
        with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
            repository.retain_authenticated_terminal_wire(
                record,
                _fake_authenticated_result(root, basis, intent, envelope),
            )
        assert lifecycle_v2_wire_file_name(envelope) in store.inventory().names
    else:
        for name, encoded in {
            LIFECYCLE_ROOT_FILE_NAME: root.encoded,
            lifecycle_v2_progress_file_name(intent): intent.encoded,
            lifecycle_v2_progress_file_name(record): record.encoded,
            lifecycle_v2_wire_file_name(envelope): envelope.encoded,
        }.items():
            store.inject(name, encoded)
        with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
            _repository(store, FakeLifecycleV2RetainedWireVerifier())
    assert store.close_count == 1


def test_live_ordinal_two_binds_receipt_inode_to_independent_stable_readback() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    record = _result_record(root, intent, envelope)
    store = _WireReceiptInodeMismatchArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="progress retention may have begun",
    ):
        repository.retain_authenticated_terminal_wire(
            record,
            _fake_authenticated_result(root, basis, intent, envelope),
        )

    assert lifecycle_v2_wire_file_name(envelope) in store.inventory().names
    assert lifecycle_v2_progress_file_name(record) not in store.inventory().names
    assert store.close_count == 1


def test_every_immutable_progress_receipt_proves_no_replace_publication() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    store = _MissingNoReplaceReceiptArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="progress retention may have begun",
    ):
        repository.retain_request_intent(intent, basis)

    assert lifecycle_v2_progress_file_name(intent) in store.inventory().names
    assert store.close_count == 1


def test_restart_recovery_intent_binds_exact_immediate_predecessor_transcript() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    root_transcript = repository.publish_transcript()
    repository.retain_request_intent(intent, basis)
    repository.publish_transcript()
    substituted = _recovery_intent(root, intent, root_transcript.sha256)
    store.inject(lifecycle_v2_progress_file_name(substituted), substituted.encoded)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="exact predecessor prefix",
    ):
        _repository(store)


def test_root_only_recovery_intent_rejects_identically_live_and_after_restart() -> None:
    root = _root()
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    root_transcript = repository.publish_transcript()
    recovery_intent = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=1,
        stage=LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        predecessor_sha256=root.sha256,
        effect_kind="recovery_classification",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "recovery_classification_envelope_sha256": _digest("recovery-envelope"),
                "operator_nonce_sha256": _digest("recovery-nonce"),
                "recovery_key_id": "recovery-key-1",
                "transport_authority_manifest_sha256": (root.transport_authority_manifest_sha256),
                "classified_transcript_sha256": root_transcript.sha256,
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
                "reason_code": "call_or_result_ambiguous",
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="ordinal-one request prefix",
    ):
        repository.retain_recovery_classification_intent(recovery_intent)

    store.inject(
        lifecycle_v2_progress_file_name(recovery_intent),
        recovery_intent.encoded,
    )
    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="namespace cannot be authenticated",
    ):
        _repository(store)


@pytest.mark.parametrize(
    "phase", ["before", "staging_created", "file_fsynced", "renamed", "directory_fsynced"]
)
def test_wire_publication_fault_never_advances_to_ordinal_two(phase: str) -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    envelope = _result_envelope(root, intent)
    authenticated = _fake_authenticated_result(root, basis, intent, envelope)
    record = _result_record(root, intent, envelope)
    store = FakeLifecycleV2ArtifactStore(fault=FakePublicationFault("wire_result", phase))
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    with pytest.raises(persistence.LifecycleV2RetentionUnconfirmed):
        repository.retain_authenticated_terminal_wire(record, authenticated)
    assert repository.status is persistence.LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED


def test_fake_transport_is_one_shot_and_binds_channel_prefix_and_counter() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    request = _final_request(root, basis, intent)
    request_envelope = _envelope(
        root, intent, frame_type="clean_stop_request", payload=request.encoded
    )
    response = _result_envelope(root, intent)
    transport = FakeLifecycleV2Transport(response)
    assert transport.exchange(request, request_envelope).envelope == response
    with pytest.raises(FakeLifecycleV2Fault, match="replay"):
        transport.exchange(request, request_envelope)


@pytest.mark.parametrize(
    "boundary", ["before_send", "after_send", "before_receive", "after_receive"]
)
def test_fake_transport_faults_never_become_retry_evidence(boundary: str) -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    request = _final_request(root, basis, intent)
    request_envelope = _envelope(
        root, intent, frame_type="clean_stop_request", payload=request.encoded
    )
    transport = FakeLifecycleV2Transport(_result_envelope(root, intent), fail_at=boundary)
    with pytest.raises(FakeLifecycleV2Fault, match=boundary):
        transport.exchange(request, request_envelope)
    with pytest.raises(FakeLifecycleV2Fault, match="replay"):
        transport.exchange(request, request_envelope)


def test_envelope_rejects_cross_direction_counter_payload_and_packet_excess() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    request = _final_request(root, basis, intent)
    envelope = _envelope(root, intent, frame_type="clean_stop_request", payload=request.encoded)
    fields = envelope.to_dict()
    for name, replacement in (
        ("direction", "supervisor_to_host"),
        ("message_counter", 1),
        ("payload_sha256", _digest("wrong-payload")),
    ):
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            UnverifiedLifecycleV2TransportEnvelope.capture({**fields, name: replacement})
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        decode_unverified_lifecycle_v2_transport_envelope(envelope.encoded + b" " * 262_144)


def test_fake_docker_surface_enforces_exact_serial_order_and_volume_preservation() -> None:
    root = _root()
    rejected = FakeLifecycleV2DockerEffects()
    with pytest.raises(FakeLifecycleV2Fault, match="before supervisor"):
        rejected.stop_source(root.source_container_id)
    with pytest.raises(FakeLifecycleV2Fault, match="burned"):
        rejected.stop_supervisor(root.supervisor_container_id)

    effects = FakeLifecycleV2DockerEffects()
    effects.stop_supervisor(root.supervisor_container_id)
    effects.stop_source(root.source_container_id)
    effects.remove_supervisor(root.supervisor_container_id)
    effects.remove_source(root.source_container_id)
    effects.remove_network(root.project_network_id)
    proof = effects.prove_volumes_preserved(
        "autoquanttrader-trusted-time_chrony_command_socket",
        "autoquanttrader-trusted-time_chrony_state",
    )
    assert proof.operation == "prove_volumes"
    assert effects.events == [
        "stop_supervisor",
        "stop_source",
        "remove_supervisor",
        "remove_source",
        "remove_network",
        "prove_volumes",
    ]
    assert not hasattr(effects, "delete_volume")
    assert not hasattr(effects, "request")


@pytest.mark.parametrize(
    "failed_operation",
    [
        "stop_supervisor",
        "stop_source",
        "remove_supervisor",
        "remove_source",
        "remove_network",
        "prove_volumes",
    ],
)
def test_every_fake_docker_effect_fault_burns_the_adapter(failed_operation: str) -> None:
    root = _root()
    effects = FakeLifecycleV2DockerEffects(failed_operation=failed_operation)
    calls: list[tuple[str, Callable[[], object]]] = [
        (
            "stop_supervisor",
            lambda: effects.stop_supervisor(root.supervisor_container_id),
        ),
        ("stop_source", lambda: effects.stop_source(root.source_container_id)),
        (
            "remove_supervisor",
            lambda: effects.remove_supervisor(root.supervisor_container_id),
        ),
        ("remove_source", lambda: effects.remove_source(root.source_container_id)),
        ("remove_network", lambda: effects.remove_network(root.project_network_id)),
        (
            "prove_volumes",
            lambda: effects.prove_volumes_preserved(
                "autoquanttrader-trusted-time_chrony_command_socket",
                "autoquanttrader-trusted-time_chrony_state",
            ),
        ),
    ]
    failed_call = next(call for name, call in calls if name == failed_operation)
    for name, call in calls:
        if name == failed_operation:
            with pytest.raises(FakeLifecycleV2Fault, match=failed_operation):
                call()
            break
        call()
    with pytest.raises(FakeLifecycleV2Fault, match="burned"):
        failed_call()


@pytest.mark.parametrize("failing_serialization_call", [1, 2])
def test_fake_docker_serialization_fault_burns_the_adapter(
    monkeypatch: pytest.MonkeyPatch,
    failing_serialization_call: int,
) -> None:
    root = _root()
    effects = FakeLifecycleV2DockerEffects()
    original_encoder = canonical_v2_json_bytes
    calls = 0

    def fail_selected_serialization(value: object, *, maximum_bytes: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == failing_serialization_call:
            raise TrustedTimeGracefulStopV2Rejected("injected serialization failure")
        return cast(bytes, original_encoder(value, maximum_bytes=maximum_bytes))

    monkeypatch.setattr(
        cast(Any, v2_fakes),
        "canonical_v2_json_bytes",
        fail_selected_serialization,
    )

    with pytest.raises(
        TrustedTimeGracefulStopV2Rejected,
        match="injected serialization failure",
    ):
        effects.stop_supervisor(root.supervisor_container_id)
    with pytest.raises(FakeLifecycleV2Fault, match="burned"):
        effects.stop_source(root.source_container_id)


def test_recovery_required_outcome_can_commit_but_confirmed_success_cannot() -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, _request_basis(root))
    classified_transcript = repository.publish_transcript()
    recovery_intent = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=2,
        stage=LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        predecessor_sha256=intent.sha256,
        effect_kind="recovery_classification",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "recovery_classification_envelope_sha256": _digest("recovery-envelope"),
                "operator_nonce_sha256": _digest("recovery-nonce"),
                "recovery_key_id": "recovery-key-1",
                "transport_authority_manifest_sha256": (root.transport_authority_manifest_sha256),
                "classified_transcript_sha256": classified_transcript.sha256,
                "admission_started_boottime_ns": root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
                "reason_code": "call_or_result_ambiguous",
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )
    repository.retain_recovery_classification_intent(recovery_intent)
    transcript = repository.publish_transcript()
    protocol_start = root.admission_started_boottime_ns + 10
    outcome = LifecycleV2Outcome.capture(
        {
            "contract_version": LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "recovery_required",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "ordinal": 3,
            "predecessor_sha256": recovery_intent.sha256,
            "final_stage": recovery_intent.stage.value,
            "transcript_sha256": transcript.sha256,
            "reason_code": "call_or_result_ambiguous",
            "pre_effect_binding_sha256": None,
            "post_teardown_binding_sha256": None,
            "volume_proof_sha256": None,
            "terminal_cleanup_sha256": None,
            "stop_effects_confirmed": False,
            "teardown_confirmed": False,
            "terminal_cleanup_confirmed": False,
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            "commit_protocol_started_boottime_ns": protocol_start,
            "commit_publication_authorization_deadline_boottime_ns": (
                protocol_start + 5_000_000_000
            ),
            "commit_authorized_boottime_ns": protocol_start + 1,
            "created_at_utc": UTC_TEXT,
        }
    )
    commit = LifecycleV2OutcomeCommit.capture(
        {
            "contract_version": LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "terminal_outcome_committed",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "outcome_sha256": outcome.sha256,
            "outcome_status": outcome.status,
            "transcript_sha256": transcript.sha256,
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "commit_protocol_started_boottime_ns": protocol_start,
            "commit_publication_authorization_deadline_boottime_ns": (
                protocol_start + 5_000_000_000
            ),
            "commit_authorized_boottime_ns": protocol_start + 1,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            "committed_at_utc": UTC_TEXT,
        },
        outcome=outcome,
    )
    repository.commit_recovery_outcome(outcome, commit)
    assert repository.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMITTED
    reopened = _repository(store)
    assert reopened.status is persistence.LifecycleV2RepositoryStatus.OUTCOME_COMMITTED

    success_fields = outcome.to_dict()
    success_fields.update(
        {
            "status": "confirmed_success",
            "ordinal": 23,
            "final_stage": LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED.value,
            "reason_code": "completed",
            "pre_effect_binding_sha256": _digest("pre"),
            "post_teardown_binding_sha256": _digest("post"),
            "volume_proof_sha256": _digest("volumes"),
            "terminal_cleanup_sha256": _digest("cleanup"),
            "stop_effects_confirmed": True,
            "teardown_confirmed": True,
            "terminal_cleanup_confirmed": True,
            "commit_authorized_boottime_ns": None,
        }
    )
    success = LifecycleV2Outcome.capture(success_fields)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="terminal outcome already committed",
    ):
        repository.commit_recovery_outcome(success, commit)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="terminal outcome already committed",
    ):
        repository.commit_recovery_outcome(outcome, commit)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="terminal outcome already retained",
    ):
        repository.publish_transcript()

    post_terminal = _recovery_intent(root, recovery_intent, transcript.sha256)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="terminal outcome already retained",
    ):
        repository.retain_recovery_classification_intent(post_terminal)


def test_repository_revalidates_forged_exact_type_outcome_before_commit() -> None:
    root = _root()
    basis = _request_basis(root)
    intent = _request_intent(root, basis)
    repository = _repository()
    repository.reserve_root(root)
    repository.retain_request_intent(intent, basis)
    classified_transcript = repository.publish_transcript()
    recovery_intent = _recovery_intent(root, intent, classified_transcript.sha256)
    repository.retain_recovery_classification_intent(recovery_intent)
    final_transcript = repository.publish_transcript()
    valid_outcome, valid_commit = _recovery_outcome_pair(
        root,
        recovery_intent,
        final_transcript.sha256,
    )
    forged_fields = valid_outcome.to_dict()
    forged_fields.update(
        {
            "stop_effects_confirmed": True,
            "teardown_confirmed": True,
            "terminal_cleanup_confirmed": True,
        }
    )
    forged_outcome = object.__new__(LifecycleV2Outcome)
    object.__setattr__(
        forged_outcome,
        "fields",
        FrozenJsonObject.capture(forged_fields),
    )
    forged_commit_fields = valid_commit.to_dict()
    forged_commit_fields["outcome_sha256"] = forged_outcome.sha256
    forged_commit = LifecycleV2OutcomeCommit.capture(
        forged_commit_fields,
        outcome=forged_outcome,
    )

    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="outcome proof is not canonically valid",
    ):
        repository.commit_recovery_outcome(forged_outcome, forged_commit)
    assert repository.status is persistence.LifecycleV2RepositoryStatus.RECOVERY_REQUIRED


@pytest.mark.parametrize(
    "mutated_field",
    [
        "graceful_stop_operation_id",
        "root_sha256",
        "ordinal",
        "predecessor_sha256",
        "final_stage",
        "transcript_sha256",
    ],
)
def test_restart_rejects_outcome_commit_forged_away_from_complete_prefix(
    mutated_field: str,
) -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent, _request_basis(root))
    classified_transcript = repository.publish_transcript()
    recovery_intent = _recovery_intent(root, intent, classified_transcript.sha256)
    repository.retain_recovery_classification_intent(recovery_intent)
    final_transcript = repository.publish_transcript()
    replacements: dict[str, object] = {
        "graceful_stop_operation_id": "423e4567-e89b-42d3-a456-426614174002",
        "root_sha256": _digest("substituted-root"),
        "ordinal": recovery_intent.ordinal + 2,
        "predecessor_sha256": _digest("substituted-predecessor"),
        "final_stage": LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED.value,
        "transcript_sha256": classified_transcript.sha256,
    }
    outcome, commit = _recovery_outcome_pair(
        root,
        recovery_intent,
        final_transcript.sha256,
        overrides={mutated_field: replacements[mutated_field]},
    )
    store.inject(outcome.file_name, outcome.encoded)
    store.inject(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME, commit.encoded)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="loaded root and complete retained prefix",
    ):
        _repository(store)


def test_restart_never_classifies_root_only_success_as_committed() -> None:
    root = _root()
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    transcript = repository.publish_transcript()
    protocol_start = root.admission_started_boottime_ns + 10
    outcome = LifecycleV2Outcome.capture(
        {
            "contract_version": LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "confirmed_success",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "ordinal": 23,
            "predecessor_sha256": root.sha256,
            "final_stage": LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED.value,
            "transcript_sha256": transcript.sha256,
            "reason_code": "completed",
            "pre_effect_binding_sha256": _digest("pre-effect"),
            "post_teardown_binding_sha256": _digest("post-teardown"),
            "volume_proof_sha256": _digest("volumes"),
            "terminal_cleanup_sha256": _digest("cleanup"),
            "stop_effects_confirmed": True,
            "teardown_confirmed": True,
            "terminal_cleanup_confirmed": True,
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            "commit_protocol_started_boottime_ns": protocol_start,
            "commit_publication_authorization_deadline_boottime_ns": (
                protocol_start + 5_000_000_000
            ),
            "commit_authorized_boottime_ns": None,
            "created_at_utc": UTC_TEXT,
        }
    )
    commit = LifecycleV2OutcomeCommit.capture(
        {
            "contract_version": LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "terminal_outcome_committed",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": root.graceful_stop_operation_id,
            "root_sha256": root.sha256,
            "outcome_sha256": outcome.sha256,
            "outcome_status": outcome.status,
            "transcript_sha256": transcript.sha256,
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "commit_protocol_started_boottime_ns": protocol_start,
            "commit_publication_authorization_deadline_boottime_ns": (
                protocol_start + 5_000_000_000
            ),
            "commit_authorized_boottime_ns": protocol_start + 1,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
            "committed_at_utc": UTC_TEXT,
        },
        outcome=outcome,
    )
    with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="recovery only"):
        repository.commit_recovery_outcome(outcome, commit)
    store.inject(outcome.file_name, outcome.encoded)
    store.inject(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME, commit.encoded)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="root-only namespace",
    ):
        _repository(store)


def test_recovery_classification_is_single_use_and_cannot_follow_terminal_cleanup() -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    repository = _repository()
    repository.reserve_root(root)
    repository.retain_request_intent(intent, _request_basis(root))
    classified_transcript = repository.publish_transcript()
    first_recovery = _recovery_intent(root, intent, classified_transcript.sha256)
    repository.retain_recovery_classification_intent(first_recovery)
    final_transcript = repository.publish_transcript()
    repeated_recovery = _recovery_intent(root, first_recovery, final_transcript.sha256)
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="already retained",
    ):
        repository.retain_recovery_classification_intent(repeated_recovery)

    terminal_cleanup = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=22,
        stage=LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED,
        predecessor_sha256=_digest("ordinal-21"),
        effect_kind="terminal_cleanup",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "cleanup_intent_sha256": _digest("cleanup-intent"),
                "transport_quiescence_record_sha256": _digest("quiescence"),
                "supervisor_remove_result_sha256": _digest("supervisor-remove"),
                "socket_absence_sha256": _digest("socket-absence"),
                "credential_path_absence_sha256": _digest("credential-absence"),
                "empty_mount_projection_sha256": _digest("empty-mounts"),
                "unmount_receipt_sha256": _digest("unmount"),
                "native_owner_cleanup_receipt_sha256": _digest("native-cleanup"),
                "all_private_material_unreachable": True,
                "cleanup_completed_boottime_ns": root.admission_started_boottime_ns + 20,
            }
        ),
        recorded_at_utc=UTC_TEXT,
    )
    post_cleanup = _recovery_intent(root, terminal_cleanup, _digest("terminal-transcript"))
    with pytest.raises(
        persistence.LifecycleV2RepositoryRejected,
        match="cannot follow a terminal stage",
    ):
        repository._require_stage_transition(
            post_cleanup,
            records=(terminal_cleanup,) * 22,
        )


@pytest.fixture
def _decision_receipt_registry_guard() -> Any:
    artifacts._PENDING_LOADED_RECEIPT_REGISTRY.clear()
    artifacts._LOADED_RECEIPT_REGISTRY.clear()
    yield
    artifacts._PENDING_LOADED_RECEIPT_REGISTRY.clear()
    artifacts._LOADED_RECEIPT_REGISTRY.clear()


def test_adr0112_v2_seam_binds_operation_admission_channel_and_is_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    _decision_receipt_registry_guard: Any,
) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fx._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(topology_reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        topology_reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )
    monkeypatch.setattr(image_verifier, "reviewed_input_bindings", execution_fx._reviewed_bindings)
    inputs = decision_fx._prepared_inputs(monkeypatch, tmp_path)
    receipt = decision_fx._prepare(inputs)
    loaded = decision_fx._load_pending_receipt(inputs, receipt)
    admission = v2_admission._build_injected_lifecycle_v2_admission_identity(
        graceful_stop_operation_id=decision_fx.STOP_OPERATION_ID,
        admission_sha256=_digest("admission"),
        channel_id=_digest("channel"),
    )
    snapshot = v2_admission._consume_historical_receipt_for_injected_lifecycle_v2_admission(
        loaded,
        admission_identity=admission,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert snapshot.admission_identity is admission
    assert snapshot.graceful_stop_operation_id == decision_fx.STOP_OPERATION_ID
    assert snapshot.receipt_sha256 == loaded.receipt_sha256
    assert not artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert not artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        v2_admission._consume_historical_receipt_for_injected_lifecycle_v2_admission(
            loaded,
            admission_identity=admission,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )


@pytest.mark.parametrize(
    "identity_fault",
    [
        "capability",
        "owner_pid",
        "owner_thread",
        "operation",
        "admission",
        "channel",
    ],
)
def test_adr0112_v2_identity_rejection_burns_pending_and_active_state(
    identity_fault: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    _decision_receipt_registry_guard: Any,
) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fx._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(topology_reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        topology_reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )
    monkeypatch.setattr(image_verifier, "reviewed_input_bindings", execution_fx._reviewed_bindings)
    inputs = decision_fx._prepared_inputs(monkeypatch, tmp_path)
    receipt = decision_fx._prepare(inputs)
    loaded = decision_fx._load_pending_receipt(inputs, receipt)
    admission = v2_admission._build_injected_lifecycle_v2_admission_identity(
        graceful_stop_operation_id=decision_fx.STOP_OPERATION_ID,
        admission_sha256=_digest("admission"),
        channel_id=_digest("channel"),
    )
    if identity_fault == "capability":
        admission = replace(admission, _capability=object())
    elif identity_fault == "owner_pid":
        admission = replace(admission, owner_pid=admission.owner_pid + 1)
    elif identity_fault == "owner_thread":
        admission = replace(admission, owner_thread=threading.Thread())
    elif identity_fault == "operation":
        admission = replace(
            admission,
            graceful_stop_operation_id="423e4567-e89b-42d3-a456-426614174002",
        )
    elif identity_fault == "admission":
        admission = replace(admission, admission_sha256="invalid")
    elif identity_fault == "channel":
        admission = replace(admission, channel_id="invalid")

    with pytest.raises(
        (
            v2_admission.LifecycleV2HistoricalReceiptHandoffRejected,
            artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
        )
    ):
        v2_admission._consume_historical_receipt_for_injected_lifecycle_v2_admission(
            loaded,
            admission_identity=admission,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
    assert not artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert not artifacts._LOADED_RECEIPT_REGISTRY


def test_partial_slice_is_machine_checkably_unreachable_and_stop_target_stays_closed() -> None:
    assert not any(lifecycle_v2_non_authority_facts().values())
    assert not any(persistence.lifecycle_v2_repository_non_authority_facts().values())
    assert not any(v2_admission.lifecycle_v2_admission_non_authority_facts().values())
    assert not any(fake_adapters_non_authority_facts().values())

    implementation_files = (
        ROOT / "packages/domain/trusted_time_graceful_stop_v2.py",
        ROOT / "packages/persistence/trusted_time_graceful_stop_v2.py",
        ROOT / "tests/unit/trusted_time_graceful_stop_v2_fakes.py",
        ROOT / "packages/application/trusted_time_graceful_stop_v2_admission.py",
    )
    forbidden_import_roots = {"docker", "httpx", "requests", "socket", "subprocess"}
    for path in implementation_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        imports = {
            node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert imports.isdisjoint(forbidden_import_roots)
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
            for node in ast.walk(tree)
        )

    importers: list[Path] = []
    architecture_policy_path = ROOT / "scripts/check_architecture.py"
    for root_name in ("apps", "packages", "scripts", "migrations"):
        for path in (ROOT / root_name).rglob("*.py"):
            if path in {
                ROOT / "packages/persistence/trusted_time_graceful_stop_v2.py",
                architecture_policy_path,
            }:
                continue
            if "_open_injected_lifecycle_v2_repository" in path.read_text(encoding="utf-8"):
                importers.append(path.relative_to(ROOT))
    assert importers == []

    fake_authentication_importers: list[Path] = []
    fake_authentication_symbols = (
        "_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY",
        "_authenticate_lifecycle_v2_transport_envelope_for_fake",
    )
    domain_path = ROOT / "packages/domain/trusted_time_graceful_stop_v2.py"
    for root_name in ("apps", "packages", "scripts", "migrations"):
        for path in (ROOT / root_name).rglob("*.py"):
            if path in {domain_path, architecture_policy_path}:
                continue
            source = path.read_text(encoding="utf-8")
            if any(symbol in source for symbol in fake_authentication_symbols):
                fake_authentication_importers.append(path.relative_to(ROOT))
    assert fake_authentication_importers == []

    make_lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    index = next(
        index for index, line in enumerate(make_lines) if line.startswith("trusted-time-stop:")
    )
    assert make_lines[index : index + 3] == [
        "trusted-time-stop: ## Fail closed until an effecting approved shutdown "
        "operator is implemented.",
        '\t@echo "trusted-time-stop is approval-blocked: no effecting approved '
        'shutdown operator is implemented" >&2',
        "\t@exit 2",
    ]
