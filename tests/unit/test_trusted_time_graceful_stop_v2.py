from __future__ import annotations

import ast
import base64
import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as topology_reader
from packages.application import trusted_time_graceful_stop_v2_admission as v2_admission
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION,
    LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
    LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
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
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    decode_unverified_lifecycle_v2_transport_envelope,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_non_authority_facts,
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
from tests.unit.trusted_time_graceful_stop_v2_fakes import (
    FakeLifecycleV2ArtifactStore,
    FakeLifecycleV2DockerEffects,
    FakeLifecycleV2Fault,
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
    return LifecycleV2CleanStopRequestBasis.capture(
        {
            "contract_version": LIFECYCLE_V2_CLEAN_STOP_REQUEST_BASIS_CONTRACT_VERSION,
            "service": "trusted-time-head-anchor-clean-stop-v2",
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
            "clean_stop_result_deadline_boottime_ns": (root.clean_stop_result_deadline_boottime_ns),
            "transport_cleanup_required": True,
            "transport_cleanup_deadline_boottime_ns": (
                root.clean_stop_result_deadline_boottime_ns + 5_000_000_000
            ),
            "admission_started_boottime_ns": root.admission_started_boottime_ns,
            "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        }
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


def _final_request(
    root: LifecycleV2Root,
    basis: LifecycleV2CleanStopRequestBasis,
    intent: LifecycleV2ProgressRecord,
) -> LifecycleV2CleanStopRequest:
    return LifecycleV2CleanStopRequest.from_prefix(
        basis,
        request_intent_sha256=intent.sha256,
        lifecycle_dispatch_prefix_sha256=lifecycle_v2_dispatch_prefix_sha256(root, intent),
    )


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
                "wire_publication_receipt": {"test_only": True},
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
) -> Any:
    return persistence._open_injected_lifecycle_v2_repository(
        store or FakeLifecycleV2ArtifactStore(),
        artifact_directory_path=ARTIFACT_DIRECTORY,
    )


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
    repository.retain_request_intent(intent)
    transcript = repository.publish_transcript()
    assert decode_lifecycle_v2_transcript(transcript.encoded) == transcript
    assert [entry.ordinal for entry in transcript.entries] == [0, 1]
    assert transcript.entries[1].predecessor_sha256 == root.sha256


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
    assert orphan.inventory() == ("unknown.json",)


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
        repository.retain_request_intent(intent)
    assert repository.status is persistence.LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED
    if phase in {"staging_created", "file_fsynced"}:
        assert ".post-enrollment-graceful-stop-v2-record-staging" in store.inventory()


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
    repository.retain_request_intent(intent)
    with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="does not bind|ordinal"):
        repository.retain_request_intent(intent)


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
    repository.retain_request_intent(intent)
    repository.retain_authenticated_terminal_wire(record, authenticated)
    wire_name = lifecycle_v2_wire_file_name(envelope)
    assert store.read_stable(wire_name) == envelope.encoded
    assert hashlib.sha256(store.read_stable(wire_name)).hexdigest() == envelope.sha256
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
    repository.retain_request_intent(intent)
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
    repository.retain_request_intent(intent)
    repository.retain_authenticated_terminal_wire(record, authenticated)

    with pytest.raises(
        persistence.LifecycleV2RetentionUnconfirmed,
        match="cannot reauthenticate retained wire signatures",
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
    repository.retain_request_intent(intent)
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
    assert transport.exchange(request, request_envelope).envelope is response
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
    effects = FakeLifecycleV2DockerEffects()
    with pytest.raises(FakeLifecycleV2Fault, match="before supervisor"):
        effects.stop_source(root.source_container_id)
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


def test_recovery_required_outcome_can_commit_but_confirmed_success_cannot() -> None:
    root = _root()
    intent = _request_intent(root, _request_basis(root))
    store = FakeLifecycleV2ArtifactStore()
    repository = _repository(store)
    repository.reserve_root(root)
    repository.retain_request_intent(intent)
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
    with pytest.raises(persistence.LifecycleV2RepositoryRejected, match="recovery only"):
        repository.commit_recovery_outcome(success, commit)


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
    for root_name in ("apps", "packages", "scripts"):
        for path in (ROOT / root_name).rglob("*.py"):
            if path == ROOT / "packages/persistence/trusted_time_graceful_stop_v2.py":
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
    for root_name in ("apps", "packages", "scripts"):
        for path in (ROOT / root_name).rglob("*.py"):
            if path == domain_path:
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
