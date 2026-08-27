from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.adapters.trusted_time import graceful_stop_v2_ed25519 as ed25519_adapter
from packages.adapters.trusted_time.graceful_stop_v2_ed25519 import (
    LifecycleV2TransportAuthenticationError,
    authenticate_lifecycle_v2_recovery_classification_envelope,
    authenticate_lifecycle_v2_transport_authority,
    authenticate_lifecycle_v2_transport_authority_manifest,
    authenticate_lifecycle_v2_transport_authority_selection,
    authenticate_retained_lifecycle_v2_wire,
    authenticate_root_bound_lifecycle_v2_transport_frame,
    authenticate_selected_lifecycle_v2_handshake,
    authenticated_lifecycle_v2_recovery_manifest_for_root,
    bind_authenticated_lifecycle_v2_terminal_envelope_proof,
    consume_authenticated_lifecycle_v2_recovery_classification_envelope,
    lifecycle_v2_ed25519_non_authority_facts,
)
from packages.domain import trusted_time_graceful_stop_v2_recovery as recovery_domain
from packages.domain import trusted_time_graceful_stop_v2_terminal as terminal_domain
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
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
    canonical_v2_json_bytes,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_progress_file_name,
    lifecycle_v2_wire_file_name,
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
    LifecycleV2RecoveryClassificationEnvelope,
    decode_lifecycle_v2_recovery_classification_envelope,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    CLEAN_STOP_RESULT_CONTRACT_VERSION,
    LifecycleV2CleanStopResult,
    LifecycleV2WirePublicationReceipt,
)
from packages.domain.trusted_time_graceful_stop_v2_transport import (
    CHANNEL_BINDING_CONTRACT_VERSION,
    HOST_CHANNEL_CONFIRMATION_CONTRACT_VERSION,
    HOST_HELLO_CONTRACT_VERSION,
    PROCESS_EPOCH_CONTRACT_VERSION,
    SUPERVISOR_HELLO_CONTRACT_VERSION,
    SUPERVISOR_SOCKET_PATH,
    TRANSPORT_AUTHORITY_MANIFEST_CONTRACT_VERSION,
    TRANSPORT_AUTHORITY_SELECTION_CONTRACT_VERSION,
    TRANSPORT_SERVICE,
    LifecycleV2ChannelBinding,
    LifecycleV2HostChannelConfirmation,
    LifecycleV2HostHello,
    LifecycleV2PeerCredential,
    LifecycleV2ProcessEpoch,
    LifecycleV2SocketIdentity,
    LifecycleV2SupervisorHello,
    LifecycleV2TransportAuthorityManifest,
    LifecycleV2TransportAuthoritySelection,
    decode_lifecycle_v2_host_channel_confirmation,
    decode_lifecycle_v2_host_hello,
    decode_lifecycle_v2_peer_credential,
    decode_lifecycle_v2_process_epoch,
    decode_lifecycle_v2_socket_identity,
    decode_lifecycle_v2_supervisor_hello,
    decode_lifecycle_v2_transport_authority_manifest,
    decode_lifecycle_v2_transport_authority_selection,
    lifecycle_v2_boot_epoch_sha256,
    lifecycle_v2_transport_contract_non_authority_facts,
)
from packages.persistence import trusted_time_graceful_stop_v2 as lifecycle_persistence
from tests.unit import test_trusted_time_graceful_stop_v2_terminal_hardening as terminal_fx
from tests.unit.trusted_time_graceful_stop_v2_fakes import FakeLifecycleV2ArtifactStore

ROOT_KEY_ID = "trusted-time-transport-root-ed25519-v1"
ENVIRONMENT = "test"
OPERATION_ID = "323e4567-e89b-42d3-a456-426614174006"
BOOT_UUID = "123e4567-e89b-42d3-a456-426614174000"
BOOT_SHA256 = lifecycle_v2_boot_epoch_sha256(BOOT_UUID)
UTC_TEXT = "2026-08-27T12:00:00.000000Z"
HANDSHAKE_DEADLINE = 5_000_000_000

ROOT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
HOST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
SUPERVISOR_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
RECOVERY_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _sign_canonical(
    fields: dict[str, object],
    value_type: type[Any],
    private_key: Ed25519PrivateKey,
) -> Any:
    unsigned = {**fields, "signature_ed25519_base64": _b64(bytes(64))}
    value = value_type.capture(unsigned)
    return value_type.capture(
        {
            **fields,
            "signature_ed25519_base64": _b64(private_key.sign(value.signature_input)),
        }
    )


def _sign_raw_fields(
    fields: dict[str, object],
    *,
    signature_domain: str,
    private_key: Ed25519PrivateKey,
    maximum_bytes: int,
) -> bytes:
    unsigned = dict(fields)
    unsigned.pop("signature_ed25519_base64", None)
    signature = private_key.sign(
        signature_domain.encode("ascii")
        + b"\0"
        + canonical_v2_json_bytes(unsigned, maximum_bytes=maximum_bytes)
    )
    return canonical_v2_json_bytes(
        {**unsigned, "signature_ed25519_base64": _b64(signature)},
        maximum_bytes=maximum_bytes,
    )


def _tamper_field(fields: dict[str, object], field_name: str) -> dict[str, object]:
    tampered = dict(fields)
    value = tampered[field_name]
    if field_name == "signature_ed25519_base64":
        tampered[field_name] = _b64(bytes([99]) * 64)
    elif field_name.endswith("_base64"):
        tampered[field_name] = _b64(bytes([99]) * 32)
    elif field_name.endswith("_sha256"):
        tampered[field_name] = _digest(f"tampered-{field_name}")
    elif type(value) is int:
        tampered[field_name] = value + 1
    elif value is None:
        tampered[field_name] = _digest(f"tampered-{field_name}")
    elif type(value) is dict:
        nested = dict(value)
        nested["process_nonce_base64"] = _b64(bytes([98]) * 32)
        tampered[field_name] = nested
    elif type(value) is str:
        tampered[field_name] = f"tampered-{field_name}"
    else:
        raise AssertionError(f"test fixture cannot tamper {field_name}")
    return tampered


def _manifest(
    *,
    generation: int = 1,
    predecessor: str | None = None,
    host_private_key: Ed25519PrivateKey = HOST_PRIVATE_KEY,
    supervisor_private_key: Ed25519PrivateKey = SUPERVISOR_PRIVATE_KEY,
    recovery_private_key: Ed25519PrivateKey = RECOVERY_PRIVATE_KEY,
) -> LifecycleV2TransportAuthorityManifest:
    fields: dict[str, object] = {
        "contract_version": TRANSPORT_AUTHORITY_MANIFEST_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
        "status": "transport_authority_manifest_issued",
        "environment": ENVIRONMENT,
        "generation": generation,
        "root_key_id": ROOT_KEY_ID,
        "predecessor_manifest_sha256": predecessor,
        "host_key_id": f"host-transport-key-g{generation}",
        "host_public_key_base64": _b64(_public_key(host_private_key)),
        "supervisor_key_id": f"supervisor-transport-key-g{generation}",
        "supervisor_public_key_base64": _b64(_public_key(supervisor_private_key)),
        "recovery_key_id": f"recovery-transport-key-g{generation}",
        "recovery_public_key_base64": _b64(_public_key(recovery_private_key)),
    }
    return cast(
        LifecycleV2TransportAuthorityManifest,
        _sign_canonical(fields, LifecycleV2TransportAuthorityManifest, ROOT_PRIVATE_KEY),
    )


def _selection(
    *,
    sequence: int,
    predecessor: str | None,
    selected: LifecycleV2TransportAuthorityManifest | None,
    recovery: LifecycleV2TransportAuthorityManifest | None,
    reason: str,
) -> LifecycleV2TransportAuthoritySelection:
    fields: dict[str, object] = {
        "contract_version": TRANSPORT_AUTHORITY_SELECTION_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
        "status": "transport_authority_selection_recorded",
        "environment": ENVIRONMENT,
        "selection_sequence": sequence,
        "disposition": "generation_selected" if selected is not None else "new_roots_denied",
        "selected_manifest_sha256": selected.sha256 if selected is not None else None,
        "selected_generation": selected.generation if selected is not None else None,
        "recovery_manifest_sha256": recovery.sha256 if recovery is not None else None,
        "predecessor_selection_sha256": predecessor,
        "reason_code": reason,
    }
    return cast(
        LifecycleV2TransportAuthoritySelection,
        _sign_canonical(fields, LifecycleV2TransportAuthoritySelection, ROOT_PRIVATE_KEY),
    )


def _process_epoch(role: str) -> LifecycleV2ProcessEpoch:
    supervisor = role == "supervisor"
    return LifecycleV2ProcessEpoch.capture(
        {
            "contract_version": PROCESS_EPOCH_CONTRACT_VERSION,
            "service": TRANSPORT_SERVICE,
            "status": "process_epoch_bound",
            "environment": ENVIRONMENT,
            "role": role,
            "boot_epoch_sha256": BOOT_SHA256,
            "pid": 42 if supervisor else 4242,
            "start_time_ticks": 1_000 if supervisor else 2_000,
            "pid_namespace_inode": 30 if supervisor else 20,
            "executable_path": (
                "/opt/autoquant/bin/trusted-time-supervisor"
                if supervisor
                else "/opt/autoquant/bin/trusted-time-stop-controller"
            ),
            "executable_sha256": _digest(f"{role}-executable"),
            "import_manifest_sha256": _digest(f"{role}-imports"),
            "process_nonce_base64": _b64(bytes([7 if supervisor else 6]) * 32),
            "container_id": _digest("supervisor-container") if supervisor else None,
            "image_id": f"sha256:{_digest('supervisor-image')}" if supervisor else None,
        }
    )


def _peer(role: str) -> LifecycleV2PeerCredential:
    if role == "host":
        fields: dict[str, object] = {
            "observer_role": "host",
            "peer_uid": 10_001,
            "peer_gid": 10_001,
            "peer_pid_disposition": "host_visible_supervisor",
            "peer_pid": 55_555,
            "peer_start_time_ticks": 1_000,
            "peer_pid_namespace_inode": 30,
            "peer_namespace_pid": 42,
            "peer_container_id": _digest("supervisor-container"),
            "peer_image_id": f"sha256:{_digest('supervisor-image')}",
            "peer_executable_sha256": _digest("supervisor-executable"),
        }
    else:
        fields = {
            "observer_role": "supervisor",
            "peer_uid": 0,
            "peer_gid": 0,
            "peer_pid_disposition": "host_outside_private_pid_namespace",
            "peer_pid": 0,
            "peer_start_time_ticks": None,
            "peer_pid_namespace_inode": None,
            "peer_namespace_pid": None,
            "peer_container_id": None,
            "peer_image_id": None,
            "peer_executable_sha256": None,
        }
    return LifecycleV2PeerCredential.capture(fields)


def _socket(role: str) -> LifecycleV2SocketIdentity:
    return LifecycleV2SocketIdentity.capture(
        {
            "observer_role": role,
            "absolute_path": SUPERVISOR_SOCKET_PATH,
            "mount_id": 101 if role == "host" else 201,
            "mount_parent_id": 1,
            "mount_major_minor": "0:42",
            "mount_root": "/",
            "mount_options": ["nodev", "noexec", "nosuid", "rw", "size=64K"],
            "directory_device": 50,
            "directory_inode": 51,
            "directory_uid": 0,
            "directory_gid": 10_001,
            "directory_mode": 0o770,
            "socket_device": 50,
            "socket_inode": 52,
            "socket_uid": 10_001,
            "socket_gid": 10_001,
            "socket_mode": 0o600,
        }
    )


def _host_hello(manifest: LifecycleV2TransportAuthorityManifest) -> LifecycleV2HostHello:
    process = _process_epoch("host")
    fields: dict[str, object] = {
        "contract_version": HOST_HELLO_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
        "status": "host_hello_offered",
        "protocol_version": 2,
        "environment": ENVIRONMENT,
        "direction": "host_to_supervisor",
        "message_counter": 0,
        "graceful_stop_operation_id": OPERATION_ID,
        "transport_authority_manifest_sha256": manifest.sha256,
        "key_generation": manifest.generation,
        "host_key_id": manifest.host_key_id,
        "expected_supervisor_key_id": manifest.supervisor_key_id,
        "boot_epoch_sha256": BOOT_SHA256,
        "host_process_epoch": process.to_dict(),
        "host_process_epoch_sha256": process.sha256,
        "host_challenge_base64": _b64(bytes([11]) * 32),
        "host_socket_identity_sha256": _socket("host").sha256,
        "host_peer_credential_sha256": _peer("host").sha256,
        "handshake_deadline_boottime_ns": HANDSHAKE_DEADLINE,
    }
    return cast(
        LifecycleV2HostHello,
        _sign_canonical(fields, LifecycleV2HostHello, HOST_PRIVATE_KEY),
    )


def _supervisor_hello(
    manifest: LifecycleV2TransportAuthorityManifest,
    host: LifecycleV2HostHello,
) -> LifecycleV2SupervisorHello:
    process = _process_epoch("supervisor")
    channel = LifecycleV2ChannelBinding.from_host_hello(
        host,
        supervisor_process_epoch=process,
        supervisor_key_id=manifest.supervisor_key_id,
        supervisor_challenge_base64=_b64(bytes([12]) * 32),
        supervisor_socket_identity_sha256=_socket("supervisor").sha256,
        supervisor_peer_credential_sha256=_peer("supervisor").sha256,
    )
    host_fields = host.to_dict()
    channel_fields = channel.to_dict()
    fields: dict[str, object] = {
        "contract_version": SUPERVISOR_HELLO_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
        "status": "supervisor_hello_accepted",
        "protocol_version": 2,
        "environment": ENVIRONMENT,
        "direction": "supervisor_to_host",
        "message_counter": 0,
        "graceful_stop_operation_id": OPERATION_ID,
        "transport_authority_manifest_sha256": manifest.sha256,
        "key_generation": manifest.generation,
        "host_key_id": manifest.host_key_id,
        "supervisor_key_id": manifest.supervisor_key_id,
        "boot_epoch_sha256": BOOT_SHA256,
        "host_hello_sha256": host.sha256,
        "host_process_epoch_sha256": host_fields["host_process_epoch_sha256"],
        "supervisor_process_epoch": process.to_dict(),
        "supervisor_process_epoch_sha256": process.sha256,
        "host_challenge_base64": host_fields["host_challenge_base64"],
        "supervisor_challenge_base64": channel_fields["supervisor_challenge_base64"],
        "host_socket_identity_sha256": host_fields["host_socket_identity_sha256"],
        "supervisor_socket_identity_sha256": channel_fields["supervisor_socket_identity_sha256"],
        "host_peer_credential_sha256": host_fields["host_peer_credential_sha256"],
        "supervisor_peer_credential_sha256": channel_fields["supervisor_peer_credential_sha256"],
        "channel_id": channel.sha256,
        "handshake_deadline_boottime_ns": HANDSHAKE_DEADLINE,
    }
    return cast(
        LifecycleV2SupervisorHello,
        _sign_canonical(fields, LifecycleV2SupervisorHello, SUPERVISOR_PRIVATE_KEY),
    )


def _confirmation(
    manifest: LifecycleV2TransportAuthorityManifest,
    host: LifecycleV2HostHello,
    supervisor: LifecycleV2SupervisorHello,
) -> LifecycleV2HostChannelConfirmation:
    supervisor_fields = supervisor.to_dict()
    fields: dict[str, object] = {
        "contract_version": HOST_CHANNEL_CONFIRMATION_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
        "status": "host_channel_confirmed",
        "protocol_version": 2,
        "environment": ENVIRONMENT,
        "direction": "host_to_supervisor",
        "message_counter": 1,
        "graceful_stop_operation_id": OPERATION_ID,
        "transport_authority_manifest_sha256": manifest.sha256,
        "key_generation": manifest.generation,
        "host_key_id": manifest.host_key_id,
        "supervisor_key_id": manifest.supervisor_key_id,
        "boot_epoch_sha256": BOOT_SHA256,
        "host_hello_sha256": host.sha256,
        "supervisor_hello_sha256": supervisor.sha256,
        "host_process_epoch_sha256": supervisor_fields["host_process_epoch_sha256"],
        "supervisor_process_epoch_sha256": supervisor_fields["supervisor_process_epoch_sha256"],
        "channel_id": supervisor_fields["channel_id"],
        "handshake_deadline_boottime_ns": HANDSHAKE_DEADLINE,
    }
    return cast(
        LifecycleV2HostChannelConfirmation,
        _sign_canonical(fields, LifecycleV2HostChannelConfirmation, HOST_PRIVATE_KEY),
    )


def _authenticated_manifest(manifest: LifecycleV2TransportAuthorityManifest) -> Any:
    return authenticate_lifecycle_v2_transport_authority_manifest(
        manifest.encoded,
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )


def _root(manifest: LifecycleV2TransportAuthorityManifest) -> LifecycleV2Root:
    start = 1_000_000_000
    return LifecycleV2Root(
        environment=ENVIRONMENT,
        graceful_stop_operation_id=OPERATION_ID,
        graceful_stop_target_sha256=_digest("target"),
        graceful_stop_decision_v1_sha256=_digest("decision"),
        graceful_stop_operator_attestation_envelope_sha256=_digest("attestation"),
        historical_decision_receipt_sha256=_digest("historical"),
        admission_sha256=_digest("admission"),
        topology_sha256=_digest("topology"),
        topology_lease_sha256=_digest("topology-lease"),
        trusted_head_sha256=_digest("trusted-head"),
        stop_authority_sha256=_digest("stop-authority"),
        transport_authority_manifest_sha256=manifest.sha256,
        transport_key_generation=manifest.generation,
        host_transport_key_id=manifest.host_key_id,
        supervisor_transport_key_id=manifest.supervisor_key_id,
        boot_epoch_sha256=BOOT_SHA256,
        host_process_epoch_sha256=_process_epoch("host").sha256,
        supervisor_process_epoch_sha256=_process_epoch("supervisor").sha256,
        channel_id=_digest("channel"),
        supervisor_container_id=_digest("supervisor-container"),
        source_container_id=_digest("source-container"),
        project_network_id=_digest("project-network"),
        chrony_command_socket_volume_identity_sha256=_digest("command-volume"),
        chrony_state_volume_identity_sha256=_digest("state-volume"),
        admission_started_boottime_ns=start,
        clean_stop_result_deadline_boottime_ns=start + 120_000_000_000,
        operation_deadline_boottime_ns=start + 600_000_000_000,
        root_created_at_utc=UTC_TEXT,
    )


def _intent(root: LifecycleV2Root) -> LifecycleV2ProgressRecord:
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
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


def _payload(contract_version: str, *, target_bytes: int | None = None) -> bytes:
    prefix = f'{{"contract_version":"{contract_version}","padding":"'.encode()
    suffix = b'"}\n'
    if target_bytes is None:
        target_bytes = len(prefix) + len(suffix) + 1
    padding_size = target_bytes - len(prefix) - len(suffix)
    assert padding_size >= 0
    return prefix + (b"x" * padding_size) + suffix


def _envelope(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
    *,
    frame_type: str,
    payload: bytes | None = None,
) -> UnverifiedLifecycleV2TransportEnvelope:
    frame_rules = {
        "clean_stop_request": (
            "host_to_supervisor",
            2,
            LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
            root.host_transport_key_id,
            HOST_PRIVATE_KEY,
        ),
        "clean_stop_result": (
            "supervisor_to_host",
            1,
            "phase6d-trusted-time-head-anchor-clean-stop-result-v2",
            root.supervisor_transport_key_id,
            SUPERVISOR_PRIVATE_KEY,
        ),
        "clean_stop_error": (
            "supervisor_to_host",
            1,
            "phase6d-trusted-time-head-anchor-clean-stop-error-v2",
            root.supervisor_transport_key_id,
            SUPERVISOR_PRIVATE_KEY,
        ),
    }
    direction, counter, payload_contract, key_id, private_key = frame_rules[frame_type]
    exact_payload = payload or _payload(payload_contract)
    fields: dict[str, object] = {
        "contract_version": LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
        "service": TRANSPORT_SERVICE,
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
        "payload_sha256": hashlib.sha256(exact_payload).hexdigest(),
        "payload_base64": _b64(exact_payload),
    }
    unsigned_with_placeholder = {
        **fields,
        "signature_ed25519_base64": _b64(bytes(64)),
    }
    placeholder = UnverifiedLifecycleV2TransportEnvelope.capture(unsigned_with_placeholder)
    unsigned_fields = placeholder.to_dict()
    unsigned_fields.pop("signature_ed25519_base64")
    signature_input = (
        b"AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2\0"
        + canonical_v2_json_bytes(unsigned_fields, maximum_bytes=262_144)
    )
    return UnverifiedLifecycleV2TransportEnvelope.capture(
        {
            **fields,
            "signature_ed25519_base64": _b64(private_key.sign(signature_input)),
        }
    )


def _classified_transcript(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
) -> LifecycleV2Transcript:
    return LifecycleV2Transcript(
        environment=root.environment,
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        entries=(
            LifecycleV2TranscriptEntry(
                ordinal=0,
                stage=LifecycleV2Stage.ROOT_RESERVED,
                record_artifact_kind="root",
                record_contract_version=LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
                record_artifact_sha256=root.sha256,
                predecessor_sha256=None,
            ),
            LifecycleV2TranscriptEntry(
                ordinal=1,
                stage=LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED,
                record_artifact_kind="progress",
                record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                record_artifact_sha256=intent.sha256,
                predecessor_sha256=root.sha256,
            ),
        ),
    )


def _recovery_envelope(
    root: LifecycleV2Root,
    transcript: LifecycleV2Transcript,
    manifest: LifecycleV2TransportAuthorityManifest,
    *,
    nonce: bytes = bytes(range(32, 64)),
) -> LifecycleV2RecoveryClassificationEnvelope:
    fields: dict[str, object] = {
        "contract_version": RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
        "service": "trusted-time-post-enrollment-graceful-stop-lifecycle-v2",
        "status": "recovery_classification_requested",
        "environment": root.environment,
        "graceful_stop_operation_id": root.graceful_stop_operation_id,
        "root_sha256": root.sha256,
        "admission_started_boottime_ns": root.admission_started_boottime_ns,
        "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        "transcript_sha256": transcript.sha256,
        "last_ordinal": transcript.entries[-1].ordinal,
        "last_stage": transcript.entries[-1].stage.value,
        "reason_code": "call_or_result_ambiguous",
        "transport_authority_manifest_sha256": manifest.sha256,
        "key_generation": manifest.generation,
        "recovery_key_id": manifest.recovery_key_id,
        "operator_nonce_base64": _b64(nonce),
        "issued_at_utc": UTC_TEXT,
    }
    return cast(
        LifecycleV2RecoveryClassificationEnvelope,
        _sign_canonical(
            fields,
            LifecycleV2RecoveryClassificationEnvelope,
            RECOVERY_PRIVATE_KEY,
        ),
    )


def _signed_terminal_result_record(
    root: LifecycleV2Root,
    intent: LifecycleV2ProgressRecord,
    *,
    artifact_directory_path: str = "/injected/adr0121/trusted-time",
    artifact_directory_device: int = 1,
    artifact_directory_inode: int = 2,
    file_device: int = 1,
    file_inode: int = 3,
) -> tuple[UnverifiedLifecycleV2TransportEnvelope, LifecycleV2ProgressRecord]:
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    request = LifecycleV2CleanStopRequest.from_prefix(root, basis, intent)
    projection = terminal_fx._terminal_projection()
    cleanup = terminal_fx._cleanup(root, request)
    request_fields = request.to_dict()
    result = LifecycleV2CleanStopResult.capture(
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
    envelope = _envelope(
        root,
        intent,
        frame_type="clean_stop_result",
        payload=result.encoded,
    )
    authenticated = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(_manifest()),
        root=root,
        request_intent=intent,
    )
    proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof(authenticated)
    receipt_value = terminal_fx._publication_receipt_value(
        root,
        request,
        envelope,
        publication_authorized_boottime_ns=root.admission_started_boottime_ns + 3,
    )
    receipt_value.update(
        {
            "artifact_directory_path": artifact_directory_path,
            "artifact_directory_device": artifact_directory_device,
            "artifact_directory_inode": artifact_directory_inode,
            "artifact_path": f"{artifact_directory_path}/{receipt_value['file_name']}",
            "file_device": file_device,
            "file_inode": file_inode,
        }
    )
    receipt = LifecycleV2WirePublicationReceipt.capture(
        receipt_value,
        proof=proof,
        request=request,
        root=root,
    )
    evidence = terminal_fx._result_evidence_value(
        root,
        request,
        result,
        envelope,
        receipt,
    )
    return envelope, LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=2,
        stage=LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        predecessor_sha256=intent.sha256,
        effect_kind="clean_stop_result",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(evidence),
        recorded_at_utc=UTC_TEXT,
    )


def test_authority_manifest_and_selection_chains_authenticate_deterministically() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )

    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )

    assert decode_lifecycle_v2_transport_authority_manifest(manifest.encoded) == manifest
    assert decode_lifecycle_v2_transport_authority_selection(selection.encoded) == selection
    assert authority.selected_manifest is not None
    assert authority.selected_manifest.manifest == manifest
    assert authority.recovery_manifest is not None
    assert authority.recovery_manifest.manifest == manifest
    assert manifest.signature_input.startswith(
        b"AutoQuantTrader/trusted-time/graceful-stop/transport-authority/v1\0"
    )


def test_recovery_classification_is_root_prefix_and_selected_generation_bound() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    transcript = _classified_transcript(root, _intent(root))
    envelope = _recovery_envelope(root, transcript, manifest)

    authenticated = authenticate_lifecycle_v2_recovery_classification_envelope(
        envelope.encoded,
        authority=authority,
        root=root,
        classified_transcript=transcript,
    )

    assert decode_lifecycle_v2_recovery_classification_envelope(envelope.encoded) == envelope
    assert authenticated.envelope == envelope
    assert authenticated.root_sha256 == root.sha256
    assert authenticated.classified_transcript_sha256 == transcript.sha256
    assert authenticated.authority_manifest_sha256 == manifest.sha256
    assert envelope.operator_nonce_sha256 == hashlib.sha256(bytes(range(32, 64))).hexdigest()
    with pytest.raises(TypeError, match="require verification"):
        type(authenticated)()


def _authenticated_recovery_for_consumption(
    *,
    nonce: bytes,
) -> tuple[
    object,
    LifecycleV2Root,
    LifecycleV2Transcript,
    LifecycleV2RecoveryClassificationEnvelope,
]:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    transcript = _classified_transcript(root, _intent(root))
    envelope = _recovery_envelope(root, transcript, manifest, nonce=nonce)
    authenticated = authenticate_lifecycle_v2_recovery_classification_envelope(
        envelope.encoded,
        authority=authority,
        root=root,
        classified_transcript=transcript,
    )
    return authenticated, root, transcript, envelope


def test_authenticated_recovery_consumption_derives_exact_intent_and_is_one_use() -> None:
    authenticated, root, transcript, envelope = _authenticated_recovery_for_consumption(
        nonce=bytes(range(64, 96))
    )

    intent = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )

    record = intent.record
    evidence = record.evidence.to_dict()
    assert record.ordinal == 2
    assert record.predecessor_sha256 == transcript.entries[-1].record_artifact_sha256
    assert evidence == {
        "recovery_classification_envelope_sha256": envelope.sha256,
        "operator_nonce_sha256": envelope.operator_nonce_sha256,
        "recovery_key_id": envelope.recovery_key_id,
        "transport_authority_manifest_sha256": (envelope.transport_authority_manifest_sha256),
        "classified_transcript_sha256": transcript.sha256,
        "admission_started_boottime_ns": root.admission_started_boottime_ns,
        "operation_deadline_boottime_ns": root.operation_deadline_boottime_ns,
        "reason_code": envelope.reason_code,
    }
    object.__setattr__(authenticated, "_consumed", False)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="cannot be consumed"):
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            authenticated,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )

    # A second authenticated wrapper cannot replay the same root/nonce either.
    second, _, _, _ = _authenticated_recovery_for_consumption(nonce=bytes(range(64, 96)))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already consumed"):
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            second,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )


def test_authenticated_issuance_authority_is_not_exposed_as_module_state() -> None:
    for module, names in (
        (
            ed25519_adapter,
            (
                "_AUTHENTICATED_VALUE_CAPABILITY",
                "_register_authenticated_recovery_classification_issuance",
            ),
        ),
        (
            recovery_domain,
            (
                "_PRODUCTION_RECOVERY_INTENT_CAPABILITY",
                "_register_lifecycle_v2_recovery_intent_issuance",
            ),
        ),
        (
            terminal_domain,
            ("_PRODUCTION_TERMINAL_ENVELOPE_PROOF_CAPABILITY",),
        ),
    ):
        for name in names:
            assert not hasattr(module, name)


def test_domain_bridge_installers_reject_preemptive_metadata_spoofing() -> None:
    def forged_recovery_endpoint(_value: object) -> object:
        return object()

    forged_recovery_endpoint.__module__ = "packages.adapters.trusted_time.graceful_stop_v2_ed25519"
    forged_recovery_endpoint.__name__ = "consume_value"
    recovery_installer, *_ = recovery_domain._lifecycle_v2_recovery_intent_issuance_registry()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="installation"):
        recovery_installer(forged_recovery_endpoint)

    def forged_terminal_endpoint(_value: object) -> object:
        return object()

    forged_terminal_endpoint.__module__ = "packages.adapters.trusted_time.graceful_stop_v2_ed25519"
    forged_terminal_endpoint.__name__ = "unwrap"
    terminal_installer, *_ = terminal_domain._build_authenticated_terminal_proof_endpoints()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="installation"):
        terminal_installer(forged_terminal_endpoint)


@pytest.mark.parametrize(
    ("domain_module", "installer_name", "endpoint_name", "forged_name"),
    (
        (
            "trusted_time_graceful_stop_v2_recovery",
            "_install_authenticated_lifecycle_v2_recovery_adapter_endpoint",
            "_consume_authenticated_lifecycle_v2_recovery_envelope_value",
            "consume_value",
        ),
        (
            "trusted_time_graceful_stop_v2_terminal",
            "_install_authenticated_terminal_envelope_adapter_endpoint",
            "_unwrap_authenticated_lifecycle_v2_transport_envelope",
            "unwrap",
        ),
    ),
)
def test_import_domain_first_cannot_preempt_adapter_endpoint_claim(
    domain_module: str,
    installer_name: str,
    endpoint_name: str,
    forged_name: str,
) -> None:
    script = f"""
from packages.domain import {domain_module} as domain

def forged(value):
    return value

forged.__module__ = "packages.adapters.trusted_time.graceful_stop_v2_ed25519"
forged.__name__ = {forged_name!r}
installer = getattr(domain, {installer_name!r})
try:
    installer(forged)
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("forged pre-install endpoint was accepted")
from packages.adapters.trusted_time import graceful_stop_v2_ed25519 as adapter
try:
    installer(getattr(adapter, {endpoint_name!r}))
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("legitimate nested-import installation was not one-shot")
"""
    repository = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    python_executable = Path(sys.executable).with_name("python")
    completed = subprocess.run(
        [python_executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_object_new_clones_cannot_reuse_authenticated_ed25519_issuances() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authenticated_manifest = _authenticated_manifest(manifest)
    forged_manifest = object.__new__(
        ed25519_adapter.AuthenticatedLifecycleV2TransportAuthorityManifest
    )
    for name in ("manifest", "root_public_key_sha256", "_capability"):
        object.__setattr__(forged_manifest, name, getattr(authenticated_manifest, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not authenticated"):
        ed25519_adapter._require_authenticated_manifest(forged_manifest)

    authenticated_selection = authenticate_lifecycle_v2_transport_authority_selection(
        selection.encoded,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    forged_selection = object.__new__(
        ed25519_adapter.AuthenticatedLifecycleV2TransportAuthoritySelection
    )
    for name in ("selection", "root_public_key_sha256", "_capability"):
        object.__setattr__(forged_selection, name, getattr(authenticated_selection, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not authenticated"):
        ed25519_adapter._require_authenticated_selection(forged_selection)

    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    forged_authority = object.__new__(ed25519_adapter.AuthenticatedLifecycleV2TransportAuthority)
    for name in (
        "resolution",
        "authenticated_manifests",
        "authenticated_selections",
        "root_public_key_sha256",
        "_capability",
    ):
        object.__setattr__(forged_authority, name, getattr(authority, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not authenticated"):
        ed25519_adapter._require_authenticated_authority(forged_authority)

    host = _host_hello(manifest)
    supervisor = _supervisor_hello(manifest, host)
    confirmation = _confirmation(manifest, host, supervisor)
    handshake = authenticate_selected_lifecycle_v2_handshake(
        authority,
        host_hello_encoded=host.encoded,
        supervisor_hello_encoded=supervisor.encoded,
        host_confirmation_encoded=confirmation.encoded,
    )
    forged_handshake = object.__new__(ed25519_adapter.AuthenticatedLifecycleV2Handshake)
    for name in ("handshake", "authority_manifest_sha256", "_capability"):
        object.__setattr__(forged_handshake, name, getattr(handshake, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not authenticated"):
        ed25519_adapter._require_authenticated_lifecycle_v2_handshake(forged_handshake)


def test_authenticated_ed25519_issuances_are_thread_bound_without_cross_thread_burn() -> None:
    manifest = _manifest()
    authenticated_manifest = _authenticated_manifest(manifest)
    root = _root(manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type="clean_stop_result")
    failures: list[BaseException] = []

    def authenticate_on_wrong_thread() -> None:
        try:
            authenticate_root_bound_lifecycle_v2_transport_frame(
                envelope.encoded,
                authority_manifest=authenticated_manifest,
                root=root,
                request_intent=intent,
            )
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=authenticate_on_wrong_thread)
    worker.start()
    worker.join()
    assert len(failures) == 1
    assert isinstance(failures[0], LifecycleV2TransportAuthenticationError)

    authenticated = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=authenticated_manifest,
        root=root,
        request_intent=intent,
    )
    assert authenticated.envelope == envelope


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork ownership proof")
def test_authenticated_authority_issuance_is_fork_bound() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            ed25519_adapter._require_authenticated_authority(authority)
        except LifecycleV2TransportAuthenticationError:
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
    assert ed25519_adapter._require_authenticated_authority(authority) is authority


def test_object_new_clones_and_module_monkeypatches_cannot_reuse_proofs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated_recovery, root, transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([211]) * 32
    )
    forged_recovery = object.__new__(
        ed25519_adapter.AuthenticatedLifecycleV2RecoveryClassificationEnvelope
    )
    for name in (
        "envelope",
        "root_sha256",
        "classified_transcript_sha256",
        "authority_manifest_sha256",
        "_origin_pid",
        "_origin_thread",
        "_consumed",
        "_capability",
    ):
        object.__setattr__(forged_recovery, name, getattr(authenticated_recovery, name))
    monkeypatch.setattr(
        ed25519_adapter,
        "_consume_authenticated_lifecycle_v2_recovery_envelope_value",
        lambda _value: (
            authenticated_recovery.envelope,
            root.sha256,
            transcript.sha256,
            authenticated_recovery.authority_manifest_sha256,
        ),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="cannot be consumed"):
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            forged_recovery,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )
    intent = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated_recovery,
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )
    forged_intent = object.__new__(recovery_domain.LifecycleV2AuthenticatedRecoveryIntent)
    for name in (
        "record",
        "recovery_classification_envelope_sha256",
        "operator_nonce_sha256",
        "classified_transcript_sha256",
        "root_sha256",
        "_origin_pid",
        "_origin_thread",
        "_capability",
    ):
        object.__setattr__(forged_intent, name, getattr(intent, name))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="issuance snapshot"):
        recovery_domain.require_authenticated_lifecycle_v2_recovery_intent(forged_intent)

    manifest = _manifest()
    request_intent = _intent(root)
    envelope = _envelope(root, request_intent, frame_type="clean_stop_result")
    authenticated_frame = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=request_intent,
    )
    expectation = ed25519_adapter._LifecycleV2TransportFrameExpectation.from_root_and_intent(
        root,
        request_intent,
        frame_type="clean_stop_result",
    )
    forged_expectation = object.__new__(ed25519_adapter._LifecycleV2TransportFrameExpectation)
    for name in (*ed25519_adapter._EXPECTATION_FIELD_NAMES, "_capability"):
        object.__setattr__(forged_expectation, name, getattr(expectation, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="issuance"):
        ed25519_adapter._authenticate_lifecycle_v2_transport_frame(
            envelope.encoded,
            authority_manifest=_authenticated_manifest(manifest),
            expectation=forged_expectation,
        )
    forged_frame = object.__new__(ed25519_adapter.AuthenticatedLifecycleV2TransportEnvelope)
    for name in ("envelope", "authority_manifest_sha256", "signer_role", "_capability"):
        object.__setattr__(forged_frame, name, getattr(authenticated_frame, name))
    monkeypatch.setattr(
        ed25519_adapter,
        "_unwrap_authenticated_lifecycle_v2_transport_envelope",
        lambda _value: (envelope, manifest.sha256, "supervisor"),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="not valid"):
        bind_authenticated_lifecycle_v2_terminal_envelope_proof(forged_frame)
    forged_dynamic_type = type(
        "AuthenticatedLifecycleV2TransportEnvelope",
        (),
        {
            "__module__": "packages.adapters.trusted_time.graceful_stop_v2_ed25519",
        },
    )
    forged_dynamic = forged_dynamic_type()
    forged_dynamic.envelope = envelope
    forged_dynamic.authority_manifest_sha256 = manifest.sha256
    forged_dynamic.signer_role = "supervisor"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="not valid"):
        bind_authenticated_lifecycle_v2_terminal_envelope_proof(forged_dynamic)

    proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof(authenticated_frame)
    forged_proof = object.__new__(terminal_domain.LifecycleV2AuthenticatedTerminalEnvelopeProof)
    for name in ("envelope", "authority_manifest_sha256", "signer_role", "_capability"):
        object.__setattr__(forged_proof, name, getattr(proof, name))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="lacks"):
        terminal_domain._require_authenticated_terminal_envelope_proof(forged_proof)

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="installation"):
        terminal_domain._install_authenticated_terminal_envelope_adapter_endpoint(
            ed25519_adapter._unwrap_authenticated_lifecycle_v2_transport_envelope
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="installation"):
        recovery_domain._install_authenticated_lifecycle_v2_recovery_adapter_endpoint(
            ed25519_adapter._consume_authenticated_lifecycle_v2_recovery_envelope_value
        )


def test_authenticated_recovery_wrapper_rejects_cross_root_mutation_before_consume() -> None:
    authenticated, signed_root, _signed_transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([203]) * 32
    )
    manifest = _manifest()
    substituted_root = dataclasses.replace(
        signed_root,
        graceful_stop_operation_id="523e4567-e89b-42d3-a456-426614174006",
    )
    substituted_transcript = _classified_transcript(
        substituted_root,
        _intent(substituted_root),
    )
    substituted_fields = _recovery_envelope(
        substituted_root,
        substituted_transcript,
        manifest,
        nonce=bytes([204]) * 32,
    ).to_dict()
    substituted_fields["signature_ed25519_base64"] = _b64(bytes(64))
    substituted_envelope = LifecycleV2RecoveryClassificationEnvelope.capture(substituted_fields)
    object.__setattr__(authenticated, "envelope", substituted_envelope)
    object.__setattr__(authenticated, "root_sha256", substituted_root.sha256)
    object.__setattr__(
        authenticated,
        "classified_transcript_sha256",
        substituted_transcript.sha256,
    )

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="cannot be consumed"):
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            authenticated,
            root=substituted_root,
            classified_transcript=substituted_transcript,
            recorded_at_utc=UTC_TEXT,
        )


def test_authenticated_recovery_wrapper_burns_before_downstream_base_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated, root, transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([205]) * 32
    )
    original = recovery_domain._canonical_recovery_inputs
    interruption = KeyboardInterrupt("injected after authenticated unwrap")

    def interrupt(**_kwargs: object) -> Any:
        raise interruption

    monkeypatch.setattr(recovery_domain, "_canonical_recovery_inputs", interrupt)
    with pytest.raises(KeyboardInterrupt) as raised:
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            authenticated,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )
    assert raised.value is interruption

    monkeypatch.setattr(recovery_domain, "_canonical_recovery_inputs", original)
    object.__setattr__(authenticated, "_consumed", False)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="cannot be consumed"):
        consume_authenticated_lifecycle_v2_recovery_classification_envelope(
            authenticated,
            root=root,
            classified_transcript=transcript,
            recorded_at_utc=UTC_TEXT,
        )


def test_authenticated_recovery_intent_rejects_same_root_prefix_substitution() -> None:
    authenticated, root, signed_transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([200]) * 32
    )
    sealed = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=root,
        classified_transcript=signed_transcript,
        recorded_at_utc=UTC_TEXT,
    )
    substituted_request = dataclasses.replace(
        _intent(root),
        recorded_at_utc="2026-08-27T12:00:00.000001Z",
    )
    store = FakeLifecycleV2ArtifactStore()
    repository = lifecycle_persistence._open_injected_lifecycle_v2_repository(store)
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repository.reserve_root(root)
    repository.retain_request_intent(substituted_request, basis)
    substituted_transcript = repository.publish_transcript()
    substituted_evidence = sealed.record.evidence.to_dict()
    substituted_evidence["classified_transcript_sha256"] = substituted_transcript.sha256
    object.__setattr__(
        sealed,
        "record",
        dataclasses.replace(
            sealed.record,
            predecessor_sha256=substituted_request.sha256,
            evidence=FrozenJsonObject.capture(substituted_evidence),
        ),
    )
    object.__setattr__(
        sealed,
        "classified_transcript_sha256",
        substituted_transcript.sha256,
    )

    with pytest.raises(
        lifecycle_persistence.LifecycleV2RepositoryRejected,
        match="not authenticated",
    ):
        repository.retain_recovery_classification_intent(sealed)

    assert signed_transcript.sha256 != substituted_transcript.sha256


def test_authenticated_recovery_intent_rejects_cross_root_substitution() -> None:
    authenticated, signed_root, signed_transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([201]) * 32
    )
    sealed = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=signed_root,
        classified_transcript=signed_transcript,
        recorded_at_utc=UTC_TEXT,
    )
    substituted_root = dataclasses.replace(
        signed_root,
        graceful_stop_operation_id="423e4567-e89b-42d3-a456-426614174006",
    )
    substituted_request = _intent(substituted_root)
    store = FakeLifecycleV2ArtifactStore()
    repository = lifecycle_persistence._open_injected_lifecycle_v2_repository(store)
    basis = LifecycleV2CleanStopRequestBasis.from_root(substituted_root)
    repository.reserve_root(substituted_root)
    repository.retain_request_intent(substituted_request, basis)
    substituted_transcript = repository.publish_transcript()
    substituted_evidence = sealed.record.evidence.to_dict()
    substituted_evidence["classified_transcript_sha256"] = substituted_transcript.sha256
    substituted_evidence["admission_started_boottime_ns"] = (
        substituted_root.admission_started_boottime_ns
    )
    substituted_evidence["operation_deadline_boottime_ns"] = (
        substituted_root.operation_deadline_boottime_ns
    )
    object.__setattr__(
        sealed,
        "record",
        dataclasses.replace(
            sealed.record,
            graceful_stop_operation_id=substituted_root.graceful_stop_operation_id,
            root_sha256=substituted_root.sha256,
            predecessor_sha256=substituted_request.sha256,
            deadline_boottime_ns=substituted_root.operation_deadline_boottime_ns,
            evidence=FrozenJsonObject.capture(substituted_evidence),
        ),
    )
    object.__setattr__(sealed, "root_sha256", substituted_root.sha256)
    object.__setattr__(
        sealed,
        "classified_transcript_sha256",
        substituted_transcript.sha256,
    )

    with pytest.raises(
        lifecycle_persistence.LifecycleV2RepositoryRejected,
        match="not authenticated",
    ):
        repository.retain_recovery_classification_intent(sealed)

    assert signed_root.sha256 != substituted_root.sha256


def test_authenticated_recovery_intent_is_consumed_by_first_store_attempt() -> None:
    authenticated, root, transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes([202]) * 32
    )
    sealed = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )
    basis = LifecycleV2CleanStopRequestBasis.from_root(root)
    repositories: list[object] = []
    for _ in range(2):
        repository = lifecycle_persistence._open_injected_lifecycle_v2_repository(
            FakeLifecycleV2ArtifactStore()
        )
        repository.reserve_root(root)
        repository.retain_request_intent(_intent(root), basis)
        assert repository.publish_transcript() == transcript
        repositories.append(repository)

    first, second = repositories
    first.retain_recovery_classification_intent(sealed)  # type: ignore[attr-defined]
    with pytest.raises(
        lifecycle_persistence.LifecycleV2RepositoryRejected,
        match="already consumed",
    ):
        second.retain_recovery_classification_intent(sealed)  # type: ignore[attr-defined]


def test_authenticated_recovery_consumption_is_thread_bound() -> None:
    authenticated, root, transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes(range(96, 128))
    )
    failures: list[BaseException] = []

    def consume_on_wrong_thread() -> None:
        try:
            consume_authenticated_lifecycle_v2_recovery_classification_envelope(
                authenticated,
                root=root,
                classified_transcript=transcript,
                recorded_at_utc=UTC_TEXT,
            )
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=consume_on_wrong_thread)
    worker.start()
    worker.join()

    assert len(failures) == 1
    assert isinstance(failures[0], TrustedTimeGracefulStopV2Rejected)
    intent = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )
    assert intent.record.root_sha256 == root.sha256


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork ownership proof")
def test_authenticated_recovery_consumption_is_fork_bound() -> None:
    authenticated, root, transcript, _ = _authenticated_recovery_for_consumption(
        nonce=bytes(range(128, 160))
    )
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            consume_authenticated_lifecycle_v2_recovery_classification_envelope(
                authenticated,
                root=root,
                classified_transcript=transcript,
                recorded_at_utc=UTC_TEXT,
            )
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

    intent = consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated,
        root=root,
        classified_transcript=transcript,
        recorded_at_utc=UTC_TEXT,
    )
    assert intent.record.root_sha256 == root.sha256


_RECOVERY_CLASSIFICATION_SIGNED_FIELDS = [
    "contract_version",
    "service",
    "status",
    "environment",
    "graceful_stop_operation_id",
    "root_sha256",
    "admission_started_boottime_ns",
    "operation_deadline_boottime_ns",
    "transcript_sha256",
    "last_ordinal",
    "last_stage",
    "reason_code",
    "transport_authority_manifest_sha256",
    "key_generation",
    "recovery_key_id",
    "operator_nonce_base64",
    "issued_at_utc",
    "signature_ed25519_base64",
]


@pytest.mark.parametrize("field_name", _RECOVERY_CLASSIFICATION_SIGNED_FIELDS)
def test_every_recovery_classification_signed_field_tamper_is_rejected(
    field_name: str,
) -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    transcript = _classified_transcript(root, _intent(root))
    envelope = _recovery_envelope(root, transcript, manifest)
    tampered = canonical_v2_json_bytes(
        _tamper_field(envelope.to_dict(), field_name),
        maximum_bytes=64 * 1_024,
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_lifecycle_v2_recovery_classification_envelope(
            tampered,
            authority=authority,
            root=root,
            classified_transcript=transcript,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "admission_started_boottime_ns",
        "operation_deadline_boottime_ns",
        "last_ordinal",
        "key_generation",
    ],
)
def test_recovery_classification_rejects_boolean_integer_fields(field_name: str) -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    transcript = _classified_transcript(root, _intent(root))
    fields = _recovery_envelope(root, transcript, manifest).to_dict()
    fields[field_name] = True
    encoded = _sign_raw_fields(
        fields,
        signature_domain=("AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1"),
        private_key=RECOVERY_PRIVATE_KEY,
        maximum_bytes=64 * 1_024,
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not canonical"):
        authenticate_lifecycle_v2_recovery_classification_envelope(
            encoded,
            authority=authority,
            root=root,
            classified_transcript=transcript,
        )


def test_recovery_classification_rejects_unhashable_reason_as_contract_error() -> None:
    manifest = _manifest()
    root = _root(manifest)
    transcript = _classified_transcript(root, _intent(root))
    fields = _recovery_envelope(root, transcript, manifest).to_dict()
    fields["reason_code"] = []

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="allowlisted"):
        LifecycleV2RecoveryClassificationEnvelope.capture(fields)


def test_recovery_classification_rejects_unselected_recovery_or_cross_prefix() -> None:
    manifest = _manifest()
    selected = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    denied = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=None,
        reason="initial",
    )
    selected_authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selected.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    denied_authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (denied.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    intent = _intent(root)
    transcript = _classified_transcript(root, intent)
    envelope = _recovery_envelope(root, transcript, manifest)
    drifted_intent = dataclasses.replace(
        intent,
        recorded_at_utc="2026-08-27T12:00:00.000001Z",
    )
    drifted_transcript = _classified_transcript(root, drifted_intent)

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not selected"):
        authenticate_lifecycle_v2_recovery_classification_envelope(
            envelope.encoded,
            authority=denied_authority,
            root=root,
            classified_transcript=transcript,
        )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="root, prefix"):
        authenticate_lifecycle_v2_recovery_classification_envelope(
            envelope.encoded,
            authority=selected_authority,
            root=root,
            classified_transcript=drifted_transcript,
        )


def test_recovery_classification_rejects_impossible_intermediate_prefix_stage() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    root = _root(manifest)
    intent = _intent(root)
    prefix = _classified_transcript(root, intent)
    impossible_ordinal_two_sha256 = _digest("impossible-ordinal-two")
    transcript = LifecycleV2Transcript(
        environment=root.environment,
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        entries=(
            *prefix.entries,
            LifecycleV2TranscriptEntry(
                ordinal=2,
                stage=LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
                record_artifact_kind="progress",
                record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                record_artifact_sha256=impossible_ordinal_two_sha256,
                predecessor_sha256=intent.sha256,
            ),
            LifecycleV2TranscriptEntry(
                ordinal=3,
                stage=LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
                record_artifact_kind="progress",
                record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                record_artifact_sha256=_digest("ordinal-three"),
                predecessor_sha256=impossible_ordinal_two_sha256,
            ),
        ),
    )
    envelope = _recovery_envelope(root, transcript, manifest)

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="impossible"):
        authenticate_lifecycle_v2_recovery_classification_envelope(
            envelope.encoded,
            authority=authority,
            root=root,
            classified_transcript=transcript,
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("wire_artifact_kind", "signed_error_envelope"),
        ("wire_artifact_file_name", ["not-a-file-name"]),
        ("wire_artifact_path", 1),
    ],
)
def test_terminal_transcript_entry_requires_stage_bound_digest_derived_wire_path(
    field_name: str,
    replacement: object,
) -> None:
    wire_sha256 = _digest("wire")
    file_name = f"trusted-time-post-enrollment-graceful-stop-v2-wire-result-{wire_sha256}.json"
    values: dict[str, object] = {
        "ordinal": 2,
        "stage": LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        "record_artifact_kind": "progress",
        "record_contract_version": LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
        "record_artifact_sha256": _digest("record"),
        "predecessor_sha256": _digest("intent"),
        "wire_artifact_kind": "signed_result_envelope",
        "wire_artifact_path": f"/injected/adr0121/trusted-time/{file_name}",
        "wire_artifact_file_name": file_name,
        "wire_artifact_sha256": wire_sha256,
    }
    values[field_name] = replacement

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="wire artifact"):
        LifecycleV2TranscriptEntry(**values)  # type: ignore[arg-type]


def test_rotation_is_gap_free_and_new_roots_denied_with_optional_recovery() -> None:
    manifest_one = _manifest()
    host_two = Ed25519PrivateKey.from_private_bytes(bytes(range(4, 36)))
    supervisor_two = Ed25519PrivateKey.from_private_bytes(bytes(range(5, 37)))
    recovery_two = Ed25519PrivateKey.from_private_bytes(bytes(range(6, 38)))
    manifest_two = _manifest(
        generation=2,
        predecessor=manifest_one.sha256,
        host_private_key=host_two,
        supervisor_private_key=supervisor_two,
        recovery_private_key=recovery_two,
    )
    selection_one = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest_one,
        recovery=manifest_one,
        reason="initial",
    )
    selection_two = _selection(
        sequence=2,
        predecessor=selection_one.sha256,
        selected=manifest_two,
        recovery=manifest_two,
        reason="rotation",
    )
    selection_three = _selection(
        sequence=3,
        predecessor=selection_two.sha256,
        selected=None,
        recovery=manifest_two,
        reason="administrative_hold",
    )

    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest_one.encoded, manifest_two.encoded),
        (selection_one.encoded, selection_two.encoded, selection_three.encoded),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )

    assert authority.selected_manifest is None
    assert authority.recovery_manifest is not None
    assert authority.recovery_manifest.manifest == manifest_two
    assert (
        authenticated_lifecycle_v2_recovery_manifest_for_root(
            authority,
            root_manifest_sha256=manifest_two.sha256,
            root_generation=2,
        )
        == authority.recovery_manifest
    )
    assert (
        authenticated_lifecycle_v2_recovery_manifest_for_root(
            authority,
            root_manifest_sha256=manifest_one.sha256,
            root_generation=1,
        )
        is None
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="recovery generation"):
        authenticated_lifecycle_v2_recovery_manifest_for_root(
            authority,
            root_manifest_sha256=manifest_two.sha256,
            root_generation=1,
        )

    denied_host = _host_hello(manifest_one)
    denied_supervisor = _supervisor_hello(manifest_one, denied_host)
    denied_confirmation = _confirmation(manifest_one, denied_host, denied_supervisor)
    assert not hasattr(ed25519_adapter, "authenticate_lifecycle_v2_handshake")
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="denies new roots"):
        authenticate_selected_lifecycle_v2_handshake(
            authority,
            host_hello_encoded=denied_host.encoded,
            supervisor_hello_encoded=denied_supervisor.encoded,
            host_confirmation_encoded=denied_confirmation.encoded,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "contract_version",
        "service",
        "status",
        "environment",
        "generation",
        "root_key_id",
        "predecessor_manifest_sha256",
        "host_key_id",
        "host_public_key_base64",
        "supervisor_key_id",
        "supervisor_public_key_base64",
        "recovery_key_id",
        "recovery_public_key_base64",
        "signature_ed25519_base64",
    ],
)
def test_every_manifest_signed_field_tamper_is_rejected(field_name: str) -> None:
    manifest = _manifest()
    fields = manifest.to_dict()
    if field_name == "generation":
        fields[field_name] = 2
        fields["predecessor_manifest_sha256"] = _digest("predecessor")
    elif field_name == "predecessor_manifest_sha256":
        fields["generation"] = 2
        fields[field_name] = _digest("predecessor")
    elif field_name.endswith("public_key_base64"):
        fields[field_name] = _b64(bytes([99]) * 32)
    elif field_name == "signature_ed25519_base64":
        fields[field_name] = _b64(bytes([99]) * 64)
    else:
        fields[field_name] = f"tampered-{field_name}"
    encoded = canonical_v2_json_bytes(fields, maximum_bytes=64 * 1_024)

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_lifecycle_v2_transport_authority_manifest(
            encoded,
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "contract_version",
        "service",
        "status",
        "environment",
        "selection_sequence",
        "disposition",
        "selected_manifest_sha256",
        "selected_generation",
        "recovery_manifest_sha256",
        "predecessor_selection_sha256",
        "reason_code",
        "signature_ed25519_base64",
    ],
)
def test_every_selection_signed_field_and_signature_tamper_is_rejected(
    field_name: str,
) -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    encoded = canonical_v2_json_bytes(
        _tamper_field(selection.to_dict(), field_name), maximum_bytes=64 * 1_024
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_lifecycle_v2_transport_authority_selection(
            encoded,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )


def test_authority_rejects_wrong_root_signature_and_generation_gap() -> None:
    manifest_one = _manifest()
    selection_one = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest_one,
        recovery=manifest_one,
        reason="initial",
    )
    wrong_root = Ed25519PrivateKey.from_private_bytes(bytes(range(10, 42)))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="signature"):
        authenticate_lifecycle_v2_transport_authority(
            (manifest_one.encoded,),
            (selection_one.encoded,),
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(wrong_root),
        )

    manifest_three = _manifest(
        generation=3,
        predecessor=manifest_one.sha256,
        host_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43))),
        supervisor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(12, 44))),
        recovery_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(13, 45))),
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="predecessor chain"):
        authenticate_lifecycle_v2_transport_authority(
            (manifest_one.encoded, manifest_three.encoded),
            (selection_one.encoded,),
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )


def test_rotation_rejects_role_key_id_or_public_key_reuse() -> None:
    manifest_one = _manifest()
    supervisor_two = Ed25519PrivateKey.from_private_bytes(bytes(range(14, 46)))
    recovery_two = Ed25519PrivateKey.from_private_bytes(bytes(range(15, 47)))
    manifest_two = _manifest(
        generation=2,
        predecessor=manifest_one.sha256,
        host_private_key=HOST_PRIVATE_KEY,
        supervisor_private_key=supervisor_two,
        recovery_private_key=recovery_two,
    )
    selection_one = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest_one,
        recovery=manifest_one,
        reason="initial",
    )
    selection_two = _selection(
        sequence=2,
        predecessor=selection_one.sha256,
        selected=manifest_two,
        recovery=manifest_two,
        reason="rotation",
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="predecessor chain"):
        authenticate_lifecycle_v2_transport_authority(
            (manifest_one.encoded, manifest_two.encoded),
            (selection_one.encoded, selection_two.encoded),
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )


def test_selection_rejects_noop_reselection_and_future_recovery_manifest() -> None:
    manifest_one = _manifest()
    manifest_two = _manifest(
        generation=2,
        predecessor=manifest_one.sha256,
        host_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(16, 48))),
        supervisor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(17, 49))),
        recovery_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(18, 50))),
    )
    selection_one = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest_one,
        recovery=manifest_one,
        reason="initial",
    )
    repeated = _selection(
        sequence=2,
        predecessor=selection_one.sha256,
        selected=manifest_one,
        recovery=manifest_one,
        reason="rotation",
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="predecessor chain"):
        authenticate_lifecycle_v2_transport_authority(
            (manifest_one.encoded,),
            (selection_one.encoded, repeated.encoded),
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )

    future_recovery = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest_one,
        recovery=manifest_two,
        reason="initial",
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="predecessor chain"):
        authenticate_lifecycle_v2_transport_authority(
            (manifest_one.encoded, manifest_two.encoded),
            (future_recovery.encoded,),
            reviewed_root_key_id=ROOT_KEY_ID,
            reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
        )


def test_authenticated_authority_rejects_offline_root_identity_role_reuse() -> None:
    manifest = _manifest()
    for key_id_field in ("host_key_id", "supervisor_key_id", "recovery_key_id"):
        fields = manifest.to_dict()
        fields.pop("signature_ed25519_base64")
        fields[key_id_field] = ROOT_KEY_ID
        key_id_reuse = cast(
            LifecycleV2TransportAuthorityManifest,
            _sign_canonical(fields, LifecycleV2TransportAuthorityManifest, ROOT_PRIVATE_KEY),
        )
        with pytest.raises(LifecycleV2TransportAuthenticationError, match="cannot be reused"):
            _authenticated_manifest(key_id_reuse)

    for public_key_reuse in (
        _manifest(host_private_key=ROOT_PRIVATE_KEY),
        _manifest(supervisor_private_key=ROOT_PRIVATE_KEY),
        _manifest(recovery_private_key=ROOT_PRIVATE_KEY),
    ):
        with pytest.raises(LifecycleV2TransportAuthenticationError, match="cannot be reused"):
            _authenticated_manifest(public_key_reuse)


def test_boot_process_peer_and_socket_identity_codecs_are_role_exact() -> None:
    host_process = _process_epoch("host")
    supervisor_process = _process_epoch("supervisor")
    host_peer = _peer("host")
    supervisor_peer = _peer("supervisor")
    host_socket = _socket("host")
    supervisor_socket = _socket("supervisor")

    assert lifecycle_v2_boot_epoch_sha256(BOOT_UUID) == BOOT_SHA256
    assert decode_lifecycle_v2_process_epoch(host_process.encoded) == host_process
    assert decode_lifecycle_v2_process_epoch(supervisor_process.encoded) == supervisor_process
    assert decode_lifecycle_v2_peer_credential(host_peer.encoded) == host_peer
    assert decode_lifecycle_v2_peer_credential(supervisor_peer.encoded) == supervisor_peer
    assert decode_lifecycle_v2_socket_identity(host_socket.encoded) == host_socket
    assert decode_lifecycle_v2_socket_identity(supervisor_socket.encoded) == supervisor_socket
    assert host_socket.sha256 != supervisor_socket.sha256

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="boot UUID"):
        lifecycle_v2_boot_epoch_sha256(BOOT_UUID.upper())
    bad_peer = supervisor_peer.to_dict()
    bad_peer["peer_pid"] = 1
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="PID-zero"):
        LifecycleV2PeerCredential.capture(bad_peer)
    bad_peer["peer_pid"] = False
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="PID-zero"):
        LifecycleV2PeerCredential.capture(bad_peer)
    bad_socket = host_socket.to_dict()
    bad_socket["mount_options"] = ["rw", "nodev"]
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="sorted"):
        LifecycleV2SocketIdentity.capture(bad_socket)


def test_process_epoch_path_and_nonce_bounds_are_exact() -> None:
    fields = _process_epoch("host").to_dict()
    fields["executable_path"] = "/" + ("a" * 254)
    assert (
        len(cast(str, LifecycleV2ProcessEpoch.capture(fields).to_dict()["executable_path"])) == 255
    )

    fields["executable_path"] = "/" + ("a" * 255)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="absolute path"):
        LifecycleV2ProcessEpoch.capture(fields)
    fields = _process_epoch("host").to_dict()
    fields["process_nonce_base64"] = _b64(bytes(31))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="process_nonce_base64"):
        LifecycleV2ProcessEpoch.capture(fields)


def test_hello_identifier_and_challenge_boundaries_are_exact() -> None:
    host = _host_hello(_manifest())
    fields = host.to_dict()
    fields["graceful_stop_operation_id"] = "a" * 128
    assert LifecycleV2HostHello.capture(fields).to_dict()["graceful_stop_operation_id"] == "a" * 128

    fields["graceful_stop_operation_id"] = "a" * 129
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="identifier"):
        LifecycleV2HostHello.capture(fields)
    for challenge_size in (31, 33):
        fields = host.to_dict()
        fields["host_challenge_base64"] = _b64(bytes(challenge_size))
        with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="host_challenge_base64"):
            LifecycleV2HostHello.capture(fields)


def test_three_signed_hellos_authenticate_and_bind_one_channel() -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    host = _host_hello(manifest)
    supervisor = _supervisor_hello(manifest, host)
    confirmation = _confirmation(manifest, host, supervisor)

    authenticated = authenticate_selected_lifecycle_v2_handshake(
        authority,
        host_hello_encoded=host.encoded,
        supervisor_hello_encoded=supervisor.encoded,
        host_confirmation_encoded=confirmation.encoded,
    )

    assert decode_lifecycle_v2_host_hello(host.encoded) == host
    assert decode_lifecycle_v2_supervisor_hello(supervisor.encoded) == supervisor
    assert decode_lifecycle_v2_host_channel_confirmation(confirmation.encoded) == confirmation
    assert authenticated.handshake.channel_id == supervisor.to_dict()["channel_id"]
    assert authenticated.handshake.channel_binding.to_dict()["contract_version"] == (
        CHANNEL_BINDING_CONTRACT_VERSION
    )


@pytest.mark.parametrize(
    ("message_name", "boolean_counter", "signature_domain", "private_key"),
    [
        (
            "host",
            False,
            "AutoQuantTrader/trusted-time/graceful-stop/host-hello/v2",
            HOST_PRIVATE_KEY,
        ),
        (
            "supervisor",
            False,
            "AutoQuantTrader/trusted-time/graceful-stop/supervisor-hello/v2",
            SUPERVISOR_PRIVATE_KEY,
        ),
        (
            "confirmation",
            True,
            "AutoQuantTrader/trusted-time/graceful-stop/host-channel-confirmation/v2",
            HOST_PRIVATE_KEY,
        ),
    ],
)
def test_correctly_signed_boolean_handshake_counters_are_rejected(
    message_name: str,
    boolean_counter: bool,
    signature_domain: str,
    private_key: Ed25519PrivateKey,
) -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    host = _host_hello(manifest)
    supervisor = _supervisor_hello(manifest, host)
    confirmation = _confirmation(manifest, host, supervisor)
    messages = {
        "host": host.encoded,
        "supervisor": supervisor.encoded,
        "confirmation": confirmation.encoded,
    }
    value_by_name: dict[str, Any] = {
        "host": host,
        "supervisor": supervisor,
        "confirmation": confirmation,
    }
    tampered = value_by_name[message_name].to_dict()
    tampered["message_counter"] = boolean_counter
    messages[message_name] = _sign_raw_fields(
        tampered,
        signature_domain=signature_domain,
        private_key=private_key,
        maximum_bytes=12_288,
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="not canonical"):
        authenticate_selected_lifecycle_v2_handshake(
            authority,
            host_hello_encoded=messages["host"],
            supervisor_hello_encoded=messages["supervisor"],
            host_confirmation_encoded=messages["confirmation"],
        )


_HOST_HELLO_SIGNED_FIELDS = [
    "contract_version",
    "service",
    "status",
    "protocol_version",
    "environment",
    "direction",
    "message_counter",
    "graceful_stop_operation_id",
    "transport_authority_manifest_sha256",
    "key_generation",
    "host_key_id",
    "expected_supervisor_key_id",
    "boot_epoch_sha256",
    "host_process_epoch",
    "host_process_epoch_sha256",
    "host_challenge_base64",
    "host_socket_identity_sha256",
    "host_peer_credential_sha256",
    "handshake_deadline_boottime_ns",
    "signature_ed25519_base64",
]
_SUPERVISOR_HELLO_SIGNED_FIELDS = [
    "contract_version",
    "service",
    "status",
    "protocol_version",
    "environment",
    "direction",
    "message_counter",
    "graceful_stop_operation_id",
    "transport_authority_manifest_sha256",
    "key_generation",
    "host_key_id",
    "supervisor_key_id",
    "boot_epoch_sha256",
    "host_hello_sha256",
    "host_process_epoch_sha256",
    "supervisor_process_epoch",
    "supervisor_process_epoch_sha256",
    "host_challenge_base64",
    "supervisor_challenge_base64",
    "host_socket_identity_sha256",
    "supervisor_socket_identity_sha256",
    "host_peer_credential_sha256",
    "supervisor_peer_credential_sha256",
    "channel_id",
    "handshake_deadline_boottime_ns",
    "signature_ed25519_base64",
]
_HOST_CONFIRMATION_SIGNED_FIELDS = [
    "contract_version",
    "service",
    "status",
    "protocol_version",
    "environment",
    "direction",
    "message_counter",
    "graceful_stop_operation_id",
    "transport_authority_manifest_sha256",
    "key_generation",
    "host_key_id",
    "supervisor_key_id",
    "boot_epoch_sha256",
    "host_hello_sha256",
    "supervisor_hello_sha256",
    "host_process_epoch_sha256",
    "supervisor_process_epoch_sha256",
    "channel_id",
    "handshake_deadline_boottime_ns",
    "signature_ed25519_base64",
]


@pytest.mark.parametrize(
    ("message_name", "field_name"),
    [
        *(("host", field_name) for field_name in _HOST_HELLO_SIGNED_FIELDS),
        *(("supervisor", field_name) for field_name in _SUPERVISOR_HELLO_SIGNED_FIELDS),
        *(("confirmation", field_name) for field_name in _HOST_CONFIRMATION_SIGNED_FIELDS),
    ],
)
def test_every_handshake_signed_field_and_signature_tamper_is_rejected(
    message_name: str,
    field_name: str,
) -> None:
    manifest = _manifest()
    selection = _selection(
        sequence=1,
        predecessor=None,
        selected=manifest,
        recovery=manifest,
        reason="initial",
    )
    authority = authenticate_lifecycle_v2_transport_authority(
        (manifest.encoded,),
        (selection.encoded,),
        reviewed_root_key_id=ROOT_KEY_ID,
        reviewed_root_public_key=_public_key(ROOT_PRIVATE_KEY),
    )
    host = _host_hello(manifest)
    supervisor = _supervisor_hello(manifest, host)
    confirmation = _confirmation(manifest, host, supervisor)
    messages = {
        "host": host.encoded,
        "supervisor": supervisor.encoded,
        "confirmation": confirmation.encoded,
    }
    value_by_name: dict[str, Any] = {
        "host": host,
        "supervisor": supervisor,
        "confirmation": confirmation,
    }
    messages[message_name] = canonical_v2_json_bytes(
        _tamper_field(value_by_name[message_name].to_dict(), field_name),
        maximum_bytes=12_288,
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_selected_lifecycle_v2_handshake(
            authority,
            host_hello_encoded=messages["host"],
            supervisor_hello_encoded=messages["supervisor"],
            host_confirmation_encoded=messages["confirmation"],
        )


@pytest.mark.parametrize(
    "frame_type",
    ["clean_stop_request", "clean_stop_result", "clean_stop_error"],
)
def test_ed25519_authenticator_verifies_every_transport_frame_role(frame_type: str) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type=frame_type)
    authenticated = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )

    assert authenticated.envelope == envelope
    assert authenticated.signer_role == (
        "host" if frame_type == "clean_stop_request" else "supervisor"
    )


@pytest.mark.parametrize("frame_type", ["clean_stop_result", "clean_stop_error"])
def test_authenticated_terminal_frame_crosses_the_private_proof_seam(
    frame_type: str,
) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type=frame_type)
    authenticated = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )

    proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof(authenticated)

    assert proof.envelope == envelope
    assert proof.authority_manifest_sha256 == root.transport_authority_manifest_sha256
    assert proof.signer_role == "supervisor"


def test_terminal_proof_seam_rejects_raw_or_non_terminal_envelopes() -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    result_envelope = _envelope(root, intent, frame_type="clean_stop_result")
    request_envelope = _envelope(root, intent, frame_type="clean_stop_request")
    authenticated_request = authenticate_root_bound_lifecycle_v2_transport_frame(
        request_envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )

    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        bind_authenticated_lifecycle_v2_terminal_envelope_proof(result_envelope)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        bind_authenticated_lifecycle_v2_terminal_envelope_proof(authenticated_request)


def test_generic_frame_verifier_rejects_parallel_manifest_with_same_endpoint_keys() -> None:
    pinned_manifest = _manifest()
    parallel_manifest = _manifest(
        recovery_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(19, 51)))
    )
    assert pinned_manifest.sha256 != parallel_manifest.sha256
    assert pinned_manifest.host_public_key == parallel_manifest.host_public_key
    assert pinned_manifest.supervisor_public_key == parallel_manifest.supervisor_public_key
    root = _root(pinned_manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type="clean_stop_result")
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="authority generation"):
        authenticate_root_bound_lifecycle_v2_transport_frame(
            envelope.encoded,
            authority_manifest=_authenticated_manifest(parallel_manifest),
            root=root,
            request_intent=intent,
        )


def test_frame_expectation_cannot_be_constructed_or_replaced_across_root_pin() -> None:
    manifest = _manifest()
    parallel_manifest = _manifest(
        recovery_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(19, 51)))
    )
    root = _root(manifest)
    intent = _intent(root)
    expectation_type = ed25519_adapter._LifecycleV2TransportFrameExpectation
    expectation = expectation_type.from_root_and_intent(
        root,
        intent,
        frame_type="clean_stop_result",
    )

    with pytest.raises(TypeError, match="root-bound derivation"):
        expectation_type()
    with pytest.raises(TypeError, match="root-bound derivation"):
        dataclasses.replace(
            expectation,
            transport_authority_manifest_sha256=parallel_manifest.sha256,
        )


@pytest.mark.parametrize("frame_type", ["clean_stop_result", "clean_stop_error"])
def test_retained_wire_reauthentication_derives_all_correlators_from_root(
    frame_type: str,
) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type=frame_type)

    authenticated = authenticate_retained_lifecycle_v2_wire(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )

    assert authenticated.envelope.encoded == envelope.encoded
    assert authenticated.authority_manifest_sha256 == root.transport_authority_manifest_sha256


def test_repository_verifier_returns_only_its_sealed_authenticated_terminal_value() -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope, terminal_record = _signed_terminal_result_record(root, intent)
    verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )

    sealed = verifier.reauthenticate_retained_terminal_wire(
        envelope=envelope,
        root=root,
        request_intent=intent,
        terminal_record=terminal_record,
        artifact_directory_path="/injected/adr0121/trusted-time",
    )

    assert verifier.require_exact_authenticated_retained_terminal_wire(sealed) is sealed
    assert sealed.envelope == envelope
    assert sealed.authority_manifest_sha256 == manifest.sha256
    assert sealed.signer_role == "supervisor"
    assert sealed.root_sha256 == root.sha256
    assert sealed.request_intent_sha256 == intent.sha256
    assert sealed.terminal_record_sha256 == terminal_record.sha256
    assert sealed.artifact_directory_path == "/injected/adr0121/trusted-time"
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="sealed value"):
        verifier.require_exact_authenticated_retained_terminal_wire(envelope)

    generic = authenticate_retained_lifecycle_v2_wire(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="sealed value"):
        verifier.require_exact_authenticated_retained_terminal_wire(generic)

    parallel_verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="sealed value"):
        parallel_verifier.require_exact_authenticated_retained_terminal_wire(sealed)


def test_retained_wire_verifier_and_result_clones_cannot_reuse_private_fields() -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope, terminal_record = _signed_terminal_result_record(root, intent)
    verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )
    forged_verifier = object.__new__(ed25519_adapter._LifecycleV2Ed25519RetainedWireVerifier)
    for name in (
        "_authority_manifest",
        "_origin_pid",
        "_origin_thread",
        "_sealed_result_capability",
        "_capability",
    ):
        object.__setattr__(forged_verifier, name, getattr(verifier, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="owner"):
        forged_verifier._require_owner()

    sealed = verifier.reauthenticate_retained_terminal_wire(
        envelope=envelope,
        root=root,
        request_intent=intent,
        terminal_record=terminal_record,
        artifact_directory_path="/injected/adr0121/trusted-time",
    )
    forged_result = object.__new__(ed25519_adapter._LifecycleV2Ed25519RetainedWireResult)
    for name in (
        "envelope",
        "authority_manifest_sha256",
        "signer_role",
        "root_sha256",
        "request_intent_sha256",
        "terminal_record_sha256",
        "artifact_directory_path",
        "_verifier_capability",
    ):
        object.__setattr__(forged_result, name, getattr(sealed, name))
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="sealed value"):
        verifier.require_exact_authenticated_retained_terminal_wire(forged_result)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("effect_kind", "source_remove"),
        ("deadline_boottime_ns", 1),
    ],
)
def test_repository_verifier_rejects_terminal_record_top_level_substitution(
    field_name: str,
    replacement: object,
) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope, terminal_record = _signed_terminal_result_record(root, intent)
    verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="root, intent"):
        verifier.reauthenticate_retained_terminal_wire(
            envelope=envelope,
            root=root,
            request_intent=intent,
            terminal_record=dataclasses.replace(
                terminal_record,
                **{field_name: replacement},
            ),
            artifact_directory_path="/injected/adr0121/trusted-time",
        )


def test_repository_restart_accepts_the_exact_ed25519_sealed_verifier_result() -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    preliminary_envelope, _ = _signed_terminal_result_record(root, intent)
    wire_name = lifecycle_v2_wire_file_name(preliminary_envelope)
    probe_store = FakeLifecycleV2ArtifactStore()
    store_identity = probe_store.identity
    envelope, terminal_record = _signed_terminal_result_record(
        root,
        intent,
        artifact_directory_path=store_identity.artifact_directory_path,
        artifact_directory_device=store_identity.directory_device,
        artifact_directory_inode=store_identity.directory_inode,
        file_device=store_identity.directory_device,
        file_inode=FakeLifecycleV2ArtifactStore.file_inode(wire_name),
    )
    assert envelope == preliminary_envelope
    store = FakeLifecycleV2ArtifactStore(
        initial={
            LIFECYCLE_ROOT_FILE_NAME: root.encoded,
            lifecycle_v2_progress_file_name(intent): intent.encoded,
            lifecycle_v2_progress_file_name(terminal_record): terminal_record.encoded,
            wire_name: envelope.encoded,
        }
    )
    verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )

    repository = lifecycle_persistence._open_injected_lifecycle_v2_repository(
        store,
        artifact_directory_path=store_identity.artifact_directory_path,
        retained_wire_verifier=verifier,
    )

    assert repository.status is lifecycle_persistence.LifecycleV2RepositoryStatus.ROOT_RESERVED
    repository.close()


def test_repository_verifier_rejects_cross_record_path_and_nested_payload() -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope, terminal_record = _signed_terminal_result_record(root, intent)
    verifier = ed25519_adapter._build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
        _authenticated_manifest(manifest)
    )
    drifted_record = dataclasses.replace(
        terminal_record,
        predecessor_sha256=_digest("another-intent"),
    )
    structurally_signed_but_untyped = _envelope(
        root,
        intent,
        frame_type="clean_stop_result",
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="root, intent"):
        verifier.reauthenticate_retained_terminal_wire(
            envelope=envelope,
            root=root,
            request_intent=intent,
            terminal_record=drifted_record,
            artifact_directory_path="/injected/adr0121/trusted-time",
        )
    with pytest.raises(LifecycleV2TransportAuthenticationError, match="repository inputs"):
        verifier.reauthenticate_retained_terminal_wire(
            envelope=envelope,
            root=root,
            request_intent=intent,
            terminal_record=terminal_record,
            artifact_directory_path="/injected/adr0121/../trusted-time",
        )
    untyped_fields = terminal_record.to_dict()
    untyped_evidence = dict(cast(dict[str, object], untyped_fields["evidence"]))
    untyped_receipt = dict(cast(dict[str, object], untyped_evidence["wire_publication_receipt"]))
    untyped_name = (
        "trusted-time-post-enrollment-graceful-stop-v2-wire-result-"
        f"{structurally_signed_but_untyped.sha256}.json"
    )
    untyped_receipt.update(
        {
            "artifact_path": f"/injected/adr0121/trusted-time/{untyped_name}",
            "file_name": untyped_name,
            "file_size": len(structurally_signed_but_untyped.encoded),
            "signed_envelope_sha256": structurally_signed_but_untyped.sha256,
            "payload_sha256": structurally_signed_but_untyped.to_dict()["payload_sha256"],
            "signature_sha256": structurally_signed_but_untyped.signature_sha256,
        }
    )
    untyped_evidence["clean_stop_result_sha256"] = structurally_signed_but_untyped.sha256
    untyped_evidence["clean_stop_result_payload_sha256"] = (
        structurally_signed_but_untyped.to_dict()["payload_sha256"]
    )
    untyped_evidence["clean_stop_result_signature_sha256"] = (
        structurally_signed_but_untyped.signature_sha256
    )
    untyped_evidence["clean_stop_result_artifact_name"] = untyped_name
    untyped_evidence["clean_stop_result_artifact_path"] = untyped_receipt["artifact_path"]
    untyped_evidence["wire_publication_receipt"] = untyped_receipt
    untyped_evidence["wire_publication_receipt_sha256"] = hashlib.sha256(
        b"AutoQuantTrader/trusted-time/graceful-stop/"
        b"wire-envelope-publication-receipt/v2\0"
        + canonical_v2_json_bytes(untyped_receipt, maximum_bytes=262_144)
    ).hexdigest()
    untyped_record = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=root.graceful_stop_operation_id,
        root_sha256=root.sha256,
        ordinal=2,
        stage=LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
        predecessor_sha256=intent.sha256,
        effect_kind="clean_stop_result",
        deadline_boottime_ns=root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(untyped_evidence),
        recorded_at_utc=UTC_TEXT,
    )

    with pytest.raises(LifecycleV2TransportAuthenticationError, match="payload or evidence"):
        verifier.reauthenticate_retained_terminal_wire(
            envelope=structurally_signed_but_untyped,
            root=root,
            request_intent=intent,
            terminal_record=untyped_record,
            artifact_directory_path="/injected/adr0121/trusted-time",
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "contract_version",
        "service",
        "protocol_version",
        "environment",
        "direction",
        "frame_type",
        "payload_contract_version",
        "key_generation",
        "signing_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "message_counter",
        "deadline_boottime_ns",
        "payload_sha256",
        "payload_base64",
        "signature_ed25519_base64",
    ],
)
def test_every_transport_envelope_field_tamper_is_rejected(field_name: str) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    envelope = _envelope(root, intent, frame_type="clean_stop_result")
    fields = envelope.to_dict()
    if field_name in {
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "channel_id",
        "lifecycle_dispatch_prefix_sha256",
        "payload_sha256",
    }:
        fields[field_name] = _digest(f"tampered-{field_name}")
    elif field_name in {
        "protocol_version",
        "key_generation",
        "message_counter",
        "deadline_boottime_ns",
    }:
        fields[field_name] = cast(int, fields[field_name]) + 1
    elif field_name == "payload_base64":
        replacement = _payload("phase6d-trusted-time-head-anchor-clean-stop-result-v2") + b" "
        fields[field_name] = _b64(replacement)
        fields["payload_sha256"] = hashlib.sha256(replacement).hexdigest()
    elif field_name == "signature_ed25519_base64":
        fields[field_name] = _b64(bytes([44]) * 64)
    else:
        fields[field_name] = f"tampered-{field_name}"
    encoded = canonical_v2_json_bytes(fields, maximum_bytes=262_144)

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_retained_lifecycle_v2_wire(
            encoded,
            authority_manifest=_authenticated_manifest(manifest),
            root=root,
            request_intent=intent,
        )


@pytest.mark.parametrize(
    ("frame_type", "payload_contract", "payload_limit"),
    [
        (
            "clean_stop_request",
            LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
            65_536,
        ),
        (
            "clean_stop_result",
            "phase6d-trusted-time-head-anchor-clean-stop-result-v2",
            180_224,
        ),
        (
            "clean_stop_error",
            "phase6d-trusted-time-head-anchor-clean-stop-error-v2",
            32_768,
        ),
    ],
)
def test_transport_payload_exact_ceiling_authenticates_and_plus_one_rejects(
    frame_type: str,
    payload_contract: str,
    payload_limit: int,
) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)
    maximum_payload = _payload(payload_contract, target_bytes=payload_limit)
    envelope = _envelope(
        root,
        intent,
        frame_type=frame_type,
        payload=maximum_payload,
    )

    authenticated = authenticate_root_bound_lifecycle_v2_transport_frame(
        envelope.encoded,
        authority_manifest=_authenticated_manifest(manifest),
        root=root,
        request_intent=intent,
    )
    assert len(authenticated.envelope.payload) == payload_limit
    assert len(envelope.encoded) < 262_144

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="payload bound"):
        _envelope(
            root,
            intent,
            frame_type=frame_type,
            payload=_payload(payload_contract, target_bytes=payload_limit + 1),
        )


@pytest.mark.parametrize("packet_size", [262_143, 262_144, 262_145])
def test_packet_boundary_garbage_never_becomes_an_authenticated_frame(packet_size: int) -> None:
    manifest = _manifest()
    root = _root(manifest)
    intent = _intent(root)

    with pytest.raises(LifecycleV2TransportAuthenticationError):
        authenticate_retained_lifecycle_v2_wire(
            b"x" * packet_size,
            authority_manifest=_authenticated_manifest(manifest),
            root=root,
            request_intent=intent,
        )


def test_contract_and_verifier_surfaces_remain_non_authorizing() -> None:
    assert set(lifecycle_v2_transport_contract_non_authority_facts().values()) == {False}
    assert set(lifecycle_v2_ed25519_non_authority_facts().values()) == {False}
    assert not hasattr(ed25519_adapter, "LifecycleV2TransportFrameExpectation")
    assert not hasattr(ed25519_adapter, "authenticate_lifecycle_v2_transport_frame")
