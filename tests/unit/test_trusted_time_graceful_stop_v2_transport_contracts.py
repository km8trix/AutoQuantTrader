from __future__ import annotations

import base64
import dataclasses
import hashlib
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
    lifecycle_v2_ed25519_non_authority_facts,
)
from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_CLEAN_STOP_REQUEST_CONTRACT_VERSION,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    LIFECYCLE_V2_TRANSPORT_ENVELOPE_CONTRACT_VERSION,
    FrozenJsonObject,
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
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    RECOVERY_CLASSIFICATION_CONTRACT_VERSION,
    LifecycleV2RecoveryClassificationEnvelope,
    decode_lifecycle_v2_recovery_classification_envelope,
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
        "operator_nonce_base64": _b64(bytes(range(32, 64))),
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
        signature_domain=(
            "AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1"
        ),
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
