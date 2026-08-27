"""Injected Ed25519 authentication for ADR-0121 lifecycle-v2 frames.

This adapter owns no private key and performs no I/O.  Callers supply reviewed
raw public-key bytes and complete canonical messages.  The retained-wire helper
derives every expected frame correlator from an exact lifecycle root and its
durable ordinal-one intent, so a caller cannot substitute a digest-only view.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_WIRE_MAXIMUM_BYTES,
    LifecycleV2CleanStopRequest,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    decode_unverified_lifecycle_v2_transport_envelope,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_wire_file_name,
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    LifecycleV2RecoveryClassificationEnvelope,
    decode_lifecycle_v2_recovery_classification_envelope,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    _PRODUCTION_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    LifecycleV2AuthenticatedTerminalEnvelopeProof,
    LifecycleV2TerminalWireEvidence,
    _mint_authenticated_lifecycle_v2_terminal_envelope_proof,
)
from packages.domain.trusted_time_graceful_stop_v2_transport import (
    LifecycleV2Handshake,
    LifecycleV2TransportAuthorityManifest,
    LifecycleV2TransportAuthorityResolution,
    LifecycleV2TransportAuthoritySelection,
    bind_lifecycle_v2_handshake,
    decode_lifecycle_v2_host_channel_confirmation,
    decode_lifecycle_v2_host_hello,
    decode_lifecycle_v2_supervisor_hello,
    decode_lifecycle_v2_transport_authority_manifest,
    decode_lifecycle_v2_transport_authority_selection,
    lifecycle_v2_recovery_manifest_for_root,
    resolve_lifecycle_v2_transport_authority,
)

TRANSPORT_ENVELOPE_SIGNATURE_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2"
)
TRANSPORT_ENVELOPE_MAXIMUM_OVERHEAD_BYTES = 8_192

_AUTHENTICATED_VALUE_CAPABILITY = object()


class LifecycleV2TransportAuthenticationError(RuntimeError):
    """A signature or its exact admitted key/correlator binding failed closed."""


def _public_key(public_key_bytes: object) -> Ed25519PublicKey:
    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise LifecycleV2TransportAuthenticationError(
            "transport authority public key must be exactly 32 bytes"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (TypeError, ValueError):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority public key is invalid"
        ) from None


def _verify(public_key_bytes: bytes, signature_input: bytes, signature: bytes) -> None:
    try:
        _public_key(public_key_bytes).verify(signature, signature_input)
    except InvalidSignature:
        raise LifecycleV2TransportAuthenticationError(
            "lifecycle-v2 Ed25519 signature authentication failed"
        ) from None
    except LifecycleV2TransportAuthenticationError:
        raise
    except Exception:
        raise LifecycleV2TransportAuthenticationError(
            "lifecycle-v2 Ed25519 verification failed closed"
        ) from None


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportAuthorityManifest:
    manifest: LifecycleV2TransportAuthorityManifest
    root_public_key_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated authority manifests require verification")


def _authenticated_manifest(
    manifest: LifecycleV2TransportAuthorityManifest,
    root_public_key: bytes,
) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
    result = object.__new__(AuthenticatedLifecycleV2TransportAuthorityManifest)
    object.__setattr__(result, "manifest", manifest)
    object.__setattr__(
        result,
        "root_public_key_sha256",
        hashlib.sha256(root_public_key).hexdigest(),
    )
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return result


def _require_authenticated_manifest(
    value: object,
) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
    if (
        type(value) is not AuthenticatedLifecycleV2TransportAuthorityManifest
        or value._capability is not _AUTHENTICATED_VALUE_CAPABILITY
        or type(value.manifest) is not LifecycleV2TransportAuthorityManifest
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority manifest is not authenticated"
        )
    return value


def authenticate_lifecycle_v2_transport_authority_manifest(
    encoded: object,
    *,
    reviewed_root_key_id: str,
    reviewed_root_public_key: bytes,
) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
    """Decode and authenticate one manifest under the injected offline root."""

    try:
        manifest = decode_lifecycle_v2_transport_authority_manifest(encoded)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "transport authority manifest is not canonical"
        ) from error
    if type(reviewed_root_key_id) is not str or manifest.root_key_id != reviewed_root_key_id:
        raise LifecycleV2TransportAuthenticationError(
            "transport authority manifest crossed the reviewed root identity"
        )
    public_key = reviewed_root_public_key if type(reviewed_root_public_key) is bytes else b""
    if reviewed_root_key_id in {
        manifest.host_key_id,
        manifest.supervisor_key_id,
        manifest.recovery_key_id,
    } or public_key in {
        manifest.host_public_key,
        manifest.supervisor_public_key,
        manifest.recovery_public_key,
    }:
        raise LifecycleV2TransportAuthenticationError(
            "offline transport root identity cannot be reused by an endpoint role"
        )
    _verify(public_key, manifest.signature_input, manifest.signature)
    return _authenticated_manifest(manifest, public_key)


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportAuthoritySelection:
    selection: LifecycleV2TransportAuthoritySelection
    root_public_key_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated authority selections require verification")


def _authenticated_selection(
    selection: LifecycleV2TransportAuthoritySelection,
    root_public_key: bytes,
) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
    result = object.__new__(AuthenticatedLifecycleV2TransportAuthoritySelection)
    object.__setattr__(result, "selection", selection)
    object.__setattr__(
        result,
        "root_public_key_sha256",
        hashlib.sha256(root_public_key).hexdigest(),
    )
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return result


def _require_authenticated_selection(
    value: object,
) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
    if (
        type(value) is not AuthenticatedLifecycleV2TransportAuthoritySelection
        or value._capability is not _AUTHENTICATED_VALUE_CAPABILITY
        or type(value.selection) is not LifecycleV2TransportAuthoritySelection
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority selection is not authenticated"
        )
    return value


def authenticate_lifecycle_v2_transport_authority_selection(
    encoded: object,
    *,
    reviewed_root_public_key: bytes,
) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
    """Decode and authenticate one selection under the injected offline root."""

    try:
        selection = decode_lifecycle_v2_transport_authority_selection(encoded)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "transport authority selection is not canonical"
        ) from error
    public_key = reviewed_root_public_key if type(reviewed_root_public_key) is bytes else b""
    _verify(public_key, selection.signature_input, selection.signature)
    return _authenticated_selection(selection, public_key)


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportAuthority:
    resolution: LifecycleV2TransportAuthorityResolution
    authenticated_manifests: tuple[AuthenticatedLifecycleV2TransportAuthorityManifest, ...]
    authenticated_selections: tuple[AuthenticatedLifecycleV2TransportAuthoritySelection, ...]
    root_public_key_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated transport authority requires chain verification")

    @property
    def selected_manifest(self) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
        selected = self.resolution.selected_manifest
        if selected is None:
            return None
        return next(
            item for item in self.authenticated_manifests if item.manifest.sha256 == selected.sha256
        )

    @property
    def recovery_manifest(self) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
        recovery = self.resolution.recovery_manifest
        if recovery is None:
            return None
        return next(
            item for item in self.authenticated_manifests if item.manifest.sha256 == recovery.sha256
        )


def authenticate_lifecycle_v2_transport_authority(
    manifest_encoded_chain: tuple[bytes, ...],
    selection_encoded_chain: tuple[bytes, ...],
    *,
    reviewed_root_key_id: str,
    reviewed_root_public_key: bytes,
) -> AuthenticatedLifecycleV2TransportAuthority:
    """Authenticate and structurally resolve complete manifest/selection chains."""

    manifests = tuple(
        authenticate_lifecycle_v2_transport_authority_manifest(
            encoded,
            reviewed_root_key_id=reviewed_root_key_id,
            reviewed_root_public_key=reviewed_root_public_key,
        )
        for encoded in manifest_encoded_chain
    )
    selections = tuple(
        authenticate_lifecycle_v2_transport_authority_selection(
            encoded,
            reviewed_root_public_key=reviewed_root_public_key,
        )
        for encoded in selection_encoded_chain
    )
    if not manifests or not selections:
        raise LifecycleV2TransportAuthenticationError("transport authority chains cannot be empty")
    root_digest = manifests[0].root_public_key_sha256
    if any(item.root_public_key_sha256 != root_digest for item in manifests) or any(
        item.root_public_key_sha256 != root_digest for item in selections
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority chain crossed the reviewed root key"
        )
    try:
        resolution = resolve_lifecycle_v2_transport_authority(
            tuple(item.manifest for item in manifests),
            tuple(item.selection for item in selections),
        )
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "transport authority predecessor chain is invalid"
        ) from error
    result = object.__new__(AuthenticatedLifecycleV2TransportAuthority)
    object.__setattr__(result, "resolution", resolution)
    object.__setattr__(result, "authenticated_manifests", manifests)
    object.__setattr__(result, "authenticated_selections", selections)
    object.__setattr__(result, "root_public_key_sha256", root_digest)
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return result


def authenticated_lifecycle_v2_recovery_manifest_for_root(
    authority: AuthenticatedLifecycleV2TransportAuthority,
    *,
    root_manifest_sha256: object,
    root_generation: object,
) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
    """Return the authenticated recovery key only for an exact pinned root."""

    if (
        type(authority) is not AuthenticatedLifecycleV2TransportAuthority
        or authority._capability is not _AUTHENTICATED_VALUE_CAPABILITY
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority resolution is not authenticated"
        )
    try:
        recovery = lifecycle_v2_recovery_manifest_for_root(
            authority.resolution,
            root_manifest_sha256=root_manifest_sha256,
            root_generation=root_generation,
        )
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "root-pinned recovery generation is invalid"
        ) from error
    if recovery is None:
        return None
    return next(
        item
        for item in authority.authenticated_manifests
        if item.manifest.sha256 == recovery.sha256
    )


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
    envelope: LifecycleV2RecoveryClassificationEnvelope
    root_sha256: str
    classified_transcript_sha256: str
    authority_manifest_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated recovery classifications require verification")


def _require_authenticated_lifecycle_v2_recovery_classification_envelope(
    value: object,
) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
    if (
        type(value) is not AuthenticatedLifecycleV2RecoveryClassificationEnvelope
        or value._capability is not _AUTHENTICATED_VALUE_CAPABILITY
        or type(value.envelope) is not LifecycleV2RecoveryClassificationEnvelope
    ):
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification is not authenticated"
        )
    try:
        canonical = decode_lifecycle_v2_recovery_classification_envelope(
            value.envelope.encoded
        )
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "authenticated recovery classification changed under validation"
        ) from error
    if (
        canonical != value.envelope
        or canonical.root_sha256 != value.root_sha256
        or canonical.transcript_sha256 != value.classified_transcript_sha256
        or canonical.transport_authority_manifest_sha256
        != value.authority_manifest_sha256
    ):
        raise LifecycleV2TransportAuthenticationError(
            "authenticated recovery classification changed under validation"
        )
    return value


def authenticate_lifecycle_v2_recovery_classification_envelope(
    encoded: object,
    *,
    authority: AuthenticatedLifecycleV2TransportAuthority,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
    """Authenticate one recovery-only classification against its exact prefix."""

    try:
        envelope = decode_lifecycle_v2_recovery_classification_envelope(encoded)
        exact_root = decode_lifecycle_v2_root(root.encoded)
        exact_transcript = decode_lifecycle_v2_transcript(classified_transcript.encoded)
    except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification inputs are not canonical"
        ) from error
    if exact_root != root or exact_transcript != classified_transcript:
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification inputs changed under validation"
        )
    recovery = authenticated_lifecycle_v2_recovery_manifest_for_root(
        authority,
        root_manifest_sha256=exact_root.transport_authority_manifest_sha256,
        root_generation=exact_root.transport_key_generation,
    )
    if recovery is None:
        raise LifecycleV2TransportAuthenticationError(
            "root-pinned recovery classification is not selected"
        )
    manifest = recovery.manifest
    if (
        manifest.sha256 != exact_root.transport_authority_manifest_sha256
        or manifest.generation != exact_root.transport_key_generation
        or manifest.environment != exact_root.environment
        or envelope.environment != exact_root.environment
        or envelope.graceful_stop_operation_id
        != exact_root.graceful_stop_operation_id
        or envelope.root_sha256 != exact_root.sha256
        or envelope.admission_started_boottime_ns
        != exact_root.admission_started_boottime_ns
        or envelope.operation_deadline_boottime_ns
        != exact_root.operation_deadline_boottime_ns
        or envelope.transcript_sha256 != exact_transcript.sha256
        or envelope.last_ordinal != exact_transcript.entries[-1].ordinal
        or envelope.last_stage is not exact_transcript.entries[-1].stage
        or exact_transcript.environment != exact_root.environment
        or exact_transcript.graceful_stop_operation_id
        != exact_root.graceful_stop_operation_id
        or exact_transcript.root_sha256 != exact_root.sha256
        or envelope.transport_authority_manifest_sha256 != manifest.sha256
        or envelope.key_generation != manifest.generation
        or envelope.recovery_key_id != manifest.recovery_key_id
    ):
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification crossed its root, prefix, or recovery generation"
        )
    _verify(manifest.recovery_public_key, envelope.signature_input, envelope.signature)
    result = object.__new__(AuthenticatedLifecycleV2RecoveryClassificationEnvelope)
    object.__setattr__(result, "envelope", envelope)
    object.__setattr__(result, "root_sha256", exact_root.sha256)
    object.__setattr__(result, "classified_transcript_sha256", exact_transcript.sha256)
    object.__setattr__(result, "authority_manifest_sha256", manifest.sha256)
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return _require_authenticated_lifecycle_v2_recovery_classification_envelope(result)


def _require_authority_correlators(
    manifest: LifecycleV2TransportAuthorityManifest,
    fields: dict[str, object],
) -> None:
    if (
        fields["environment"] != manifest.environment
        or fields["transport_authority_manifest_sha256"] != manifest.sha256
        or fields["key_generation"] != manifest.generation
        or fields["host_key_id"] != manifest.host_key_id
    ):
        raise LifecycleV2TransportAuthenticationError(
            "handshake crossed its authenticated authority manifest"
        )


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2Handshake:
    handshake: LifecycleV2Handshake
    authority_manifest_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated handshakes require signature verification")


def _authenticate_lifecycle_v2_handshake(
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    *,
    host_hello_encoded: bytes,
    supervisor_hello_encoded: bytes,
    host_confirmation_encoded: bytes,
) -> AuthenticatedLifecycleV2Handshake:
    """Authenticate and correlate the exact three-message mutual handshake."""

    authenticated = _require_authenticated_manifest(authority_manifest)
    manifest = authenticated.manifest
    try:
        host = decode_lifecycle_v2_host_hello(host_hello_encoded)
        supervisor = decode_lifecycle_v2_supervisor_hello(supervisor_hello_encoded)
        confirmation = decode_lifecycle_v2_host_channel_confirmation(host_confirmation_encoded)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "lifecycle-v2 handshake message is not canonical"
        ) from error
    _require_authority_correlators(manifest, host.to_dict())
    _require_authority_correlators(manifest, supervisor.to_dict())
    _require_authority_correlators(manifest, confirmation.to_dict())
    if (
        host.to_dict()["expected_supervisor_key_id"] != manifest.supervisor_key_id
        or supervisor.to_dict()["supervisor_key_id"] != manifest.supervisor_key_id
        or confirmation.to_dict()["supervisor_key_id"] != manifest.supervisor_key_id
    ):
        raise LifecycleV2TransportAuthenticationError(
            "handshake crossed the authenticated supervisor key"
        )
    _verify(manifest.host_public_key, host.signature_input, host.signature)
    _verify(manifest.supervisor_public_key, supervisor.signature_input, supervisor.signature)
    _verify(manifest.host_public_key, confirmation.signature_input, confirmation.signature)
    try:
        handshake = bind_lifecycle_v2_handshake(host, supervisor, confirmation)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "authenticated handshake correlators disagree"
        ) from error
    result = object.__new__(AuthenticatedLifecycleV2Handshake)
    object.__setattr__(result, "handshake", handshake)
    object.__setattr__(result, "authority_manifest_sha256", manifest.sha256)
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return result


def authenticate_selected_lifecycle_v2_handshake(
    authority: AuthenticatedLifecycleV2TransportAuthority,
    *,
    host_hello_encoded: bytes,
    supervisor_hello_encoded: bytes,
    host_confirmation_encoded: bytes,
) -> AuthenticatedLifecycleV2Handshake:
    """Authenticate a new-root handshake only when the current selection permits it."""

    if (
        type(authority) is not AuthenticatedLifecycleV2TransportAuthority
        or authority._capability is not _AUTHENTICATED_VALUE_CAPABILITY
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport authority resolution is not authenticated"
        )
    selected = authority.selected_manifest
    if selected is None:
        raise LifecycleV2TransportAuthenticationError(
            "current transport authority selection denies new roots"
        )
    return _authenticate_lifecycle_v2_handshake(
        selected,
        host_hello_encoded=host_hello_encoded,
        supervisor_hello_encoded=supervisor_hello_encoded,
        host_confirmation_encoded=host_confirmation_encoded,
    )


@dataclass(frozen=True, slots=True, init=False)
class _LifecycleV2TransportFrameExpectation:
    environment: str
    transport_authority_manifest_sha256: str
    frame_type: str
    key_generation: int
    signing_key_id: str
    boot_epoch_sha256: str
    host_process_epoch_sha256: str
    supervisor_process_epoch_sha256: str
    channel_id: str
    lifecycle_dispatch_prefix_sha256: str
    message_counter: int
    deadline_boottime_ns: int
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport frame expectations require root-bound derivation")

    @classmethod
    def from_root_and_intent(
        cls,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        *,
        frame_type: str,
    ) -> _LifecycleV2TransportFrameExpectation:
        try:
            exact_root = decode_lifecycle_v2_root(root.encoded)
            exact_intent = decode_lifecycle_v2_progress_record(request_intent.encoded)
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire expectation requires canonical root and intent"
            ) from error
        if (
            exact_intent.ordinal != 1
            or exact_intent.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
            or exact_intent.root_sha256 != exact_root.sha256
            or exact_intent.predecessor_sha256 != exact_root.sha256
            or frame_type not in {"clean_stop_request", "clean_stop_result", "clean_stop_error"}
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire expectation does not bind the ordinal-one prefix"
            )
        host_frame = frame_type == "clean_stop_request"
        result = object.__new__(cls)
        values: dict[str, object] = {
            "environment": exact_root.environment,
            "transport_authority_manifest_sha256": (exact_root.transport_authority_manifest_sha256),
            "frame_type": frame_type,
            "key_generation": exact_root.transport_key_generation,
            "signing_key_id": (
                exact_root.host_transport_key_id
                if host_frame
                else exact_root.supervisor_transport_key_id
            ),
            "boot_epoch_sha256": exact_root.boot_epoch_sha256,
            "host_process_epoch_sha256": exact_root.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": exact_root.supervisor_process_epoch_sha256,
            "channel_id": exact_root.channel_id,
            "lifecycle_dispatch_prefix_sha256": lifecycle_v2_dispatch_prefix_sha256(
                exact_root, exact_intent
            ),
            "message_counter": 2 if host_frame else 1,
            "deadline_boottime_ns": exact_root.clean_stop_result_deadline_boottime_ns,
            "_capability": _AUTHENTICATED_VALUE_CAPABILITY,
        }
        for name, value in values.items():
            object.__setattr__(result, name, value)
        return result


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportEnvelope:
    envelope: UnverifiedLifecycleV2TransportEnvelope
    authority_manifest_sha256: str
    signer_role: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated transport envelopes require signature verification")


def _unwrap_authenticated_lifecycle_v2_transport_envelope(
    value: object,
) -> tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]:
    if (
        type(value) is not AuthenticatedLifecycleV2TransportEnvelope
        or value._capability is not _AUTHENTICATED_VALUE_CAPABILITY
        or type(value.envelope) is not UnverifiedLifecycleV2TransportEnvelope
    ):
        raise LifecycleV2TransportAuthenticationError(
            "terminal proof requires an exact authenticated transport envelope"
        )
    return value.envelope, value.authority_manifest_sha256, value.signer_role


def bind_authenticated_lifecycle_v2_terminal_envelope_proof(
    authenticated_envelope: object,
) -> LifecycleV2AuthenticatedTerminalEnvelopeProof:
    """Cross the reviewed adapter-to-domain seam for one authenticated terminal frame."""

    return _mint_authenticated_lifecycle_v2_terminal_envelope_proof(
        authenticated_envelope,
        unwrap=_unwrap_authenticated_lifecycle_v2_transport_envelope,
        capability=_PRODUCTION_TERMINAL_ENVELOPE_PROOF_CAPABILITY,
    )


def _transport_envelope_signature_input(
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> bytes:
    fields = envelope.to_dict()
    fields.pop("signature_ed25519_base64")
    unsigned = canonical_v2_json_bytes(fields, maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES)
    return TRANSPORT_ENVELOPE_SIGNATURE_DOMAIN.encode("ascii") + b"\0" + unsigned


def _validate_transport_envelope_formula(
    envelope: UnverifiedLifecycleV2TransportEnvelope,
) -> None:
    fields = envelope.to_dict()
    payload_base64 = fields["payload_base64"]
    if type(payload_base64) is not str:
        raise LifecycleV2TransportAuthenticationError("transport payload encoding is invalid")
    fields["payload_base64"] = ""
    overhead = len(canonical_v2_json_bytes(fields, maximum_bytes=LIFECYCLE_V2_WIRE_MAXIMUM_BYTES))
    expected_payload_base64_length = 4 * ((len(envelope.payload) + 2) // 3)
    if (
        overhead > TRANSPORT_ENVELOPE_MAXIMUM_OVERHEAD_BYTES
        or len(payload_base64) != expected_payload_base64_length
        or len(envelope.encoded) != overhead + expected_payload_base64_length
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport envelope overhead or base64 length formula is invalid"
        )


def _authenticate_lifecycle_v2_transport_frame(
    encoded: object,
    *,
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    expectation: _LifecycleV2TransportFrameExpectation,
) -> AuthenticatedLifecycleV2TransportEnvelope:
    """Authenticate one request, result, or error against exact correlators."""

    authenticated = _require_authenticated_manifest(authority_manifest)
    if (
        type(expectation) is not _LifecycleV2TransportFrameExpectation
        or expectation._capability is not _AUTHENTICATED_VALUE_CAPABILITY
    ):
        raise LifecycleV2TransportAuthenticationError("transport frame expectation is invalid")
    try:
        envelope = decode_unverified_lifecycle_v2_transport_envelope(encoded)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "transport envelope is not structurally canonical"
        ) from error
    _validate_transport_envelope_formula(envelope)
    fields = envelope.to_dict()
    expected_fields: dict[str, object] = {
        "environment": expectation.environment,
        "frame_type": expectation.frame_type,
        "key_generation": expectation.key_generation,
        "signing_key_id": expectation.signing_key_id,
        "boot_epoch_sha256": expectation.boot_epoch_sha256,
        "host_process_epoch_sha256": expectation.host_process_epoch_sha256,
        "supervisor_process_epoch_sha256": expectation.supervisor_process_epoch_sha256,
        "channel_id": expectation.channel_id,
        "lifecycle_dispatch_prefix_sha256": expectation.lifecycle_dispatch_prefix_sha256,
        "message_counter": expectation.message_counter,
        "deadline_boottime_ns": expectation.deadline_boottime_ns,
    }
    if any(fields[name] != expected for name, expected in expected_fields.items()):
        raise LifecycleV2TransportAuthenticationError(
            "transport envelope crossed an expected retained-wire correlator"
        )
    manifest = authenticated.manifest
    if (
        manifest.sha256 != expectation.transport_authority_manifest_sha256
        or manifest.environment != expectation.environment
        or manifest.generation != expectation.key_generation
    ):
        raise LifecycleV2TransportAuthenticationError(
            "transport frame crossed its authenticated authority generation"
        )
    if expectation.frame_type == "clean_stop_request":
        public_key = manifest.host_public_key
        expected_key_id = manifest.host_key_id
        signer_role = "host"
    else:
        public_key = manifest.supervisor_public_key
        expected_key_id = manifest.supervisor_key_id
        signer_role = "supervisor"
    if expectation.signing_key_id != expected_key_id:
        raise LifecycleV2TransportAuthenticationError(
            "transport frame crossed its authenticated signer role"
        )
    _verify(public_key, _transport_envelope_signature_input(envelope), envelope.signature)
    result = object.__new__(AuthenticatedLifecycleV2TransportEnvelope)
    object.__setattr__(result, "envelope", envelope)
    object.__setattr__(result, "authority_manifest_sha256", manifest.sha256)
    object.__setattr__(result, "signer_role", signer_role)
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    return result


def authenticate_root_bound_lifecycle_v2_transport_frame(
    encoded: object,
    *,
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    root: LifecycleV2Root,
    request_intent: LifecycleV2ProgressRecord,
) -> AuthenticatedLifecycleV2TransportEnvelope:
    """Authenticate one frame against correlators derived from its exact durable prefix."""

    try:
        envelope = decode_unverified_lifecycle_v2_transport_envelope(encoded)
        exact_root = decode_lifecycle_v2_root(root.encoded)
    except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise LifecycleV2TransportAuthenticationError(
            "root-bound lifecycle-v2 frame inputs are not canonical"
        ) from error
    expectation = _LifecycleV2TransportFrameExpectation.from_root_and_intent(
        exact_root,
        request_intent,
        frame_type=envelope.frame_type,
    )
    return _authenticate_lifecycle_v2_transport_frame(
        encoded,
        authority_manifest=authority_manifest,
        expectation=expectation,
    )


def authenticate_retained_lifecycle_v2_wire(
    encoded: object,
    *,
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    root: LifecycleV2Root,
    request_intent: LifecycleV2ProgressRecord,
) -> AuthenticatedLifecycleV2TransportEnvelope:
    """Reauthenticate one retained result/error from root-pinned authority facts."""

    authenticated = _require_authenticated_manifest(authority_manifest)
    try:
        envelope = decode_unverified_lifecycle_v2_transport_envelope(encoded)
        exact_root = decode_lifecycle_v2_root(root.encoded)
    except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise LifecycleV2TransportAuthenticationError(
            "retained lifecycle-v2 wire inputs are not canonical"
        ) from error
    if envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}:
        raise LifecycleV2TransportAuthenticationError(
            "only terminal supervisor frames are retained wire artifacts"
        )
    manifest = authenticated.manifest
    if (
        exact_root.transport_authority_manifest_sha256 != manifest.sha256
        or exact_root.transport_key_generation != manifest.generation
        or exact_root.host_transport_key_id != manifest.host_key_id
        or exact_root.supervisor_transport_key_id != manifest.supervisor_key_id
        or exact_root.environment != manifest.environment
    ):
        raise LifecycleV2TransportAuthenticationError(
            "retained root crossed its root-pinned transport authority"
        )
    expectation = _LifecycleV2TransportFrameExpectation.from_root_and_intent(
        exact_root, request_intent, frame_type=envelope.frame_type
    )
    return _authenticate_lifecycle_v2_transport_frame(
        encoded,
        authority_manifest=authenticated,
        expectation=expectation,
    )


@dataclass(frozen=True, slots=True, init=False)
class _LifecycleV2Ed25519RetainedWireVerifier:
    """Process/thread-bound injected repository verifier over one public key."""

    _authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest
    _origin_pid: int
    _origin_thread: threading.Thread
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("retained-wire verifiers require authenticated construction")

    def _require_owner(self) -> None:
        if (
            self._capability is not _AUTHENTICATED_VALUE_CAPABILITY
            or os.getpid() != self._origin_pid
            or threading.current_thread() is not self._origin_thread
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier owner is invalid"
            )
        _require_authenticated_manifest(self._authority_manifest)

    def reauthenticate_retained_terminal_wire(
        self,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        self._require_owner()
        try:
            exact_record = decode_lifecycle_v2_progress_record(terminal_record.encoded)
            exact_root = decode_lifecycle_v2_root(root.encoded)
            exact_intent = decode_lifecycle_v2_progress_record(request_intent.encoded)
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire repository values are not canonical"
            ) from error
        if (
            exact_record != terminal_record
            or exact_root != root
            or exact_intent != request_intent
            or type(envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or type(artifact_directory_path) is not str
            or not artifact_directory_path.startswith("/")
            or not artifact_directory_path.endswith("/trusted-time")
            or artifact_directory_path == "/trusted-time"
            or "//" in artifact_directory_path
            or "/./" in artifact_directory_path
            or "/../" in artifact_directory_path
            or "\0" in artifact_directory_path
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire repository inputs are not exact"
            )
        if envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier accepts only terminal frames"
            )
        prefix = (
            "clean_stop_result"
            if envelope.frame_type == "clean_stop_result"
            else "clean_stop_error"
        )
        expected_stage = (
            LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            if envelope.frame_type == "clean_stop_result"
            else LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED
        )
        evidence = exact_record.evidence.to_dict()
        file_name = lifecycle_v2_wire_file_name(envelope)
        if (
            exact_record.ordinal != 2
            or exact_record.stage is not expected_stage
            or exact_record.graceful_stop_operation_id
            != exact_root.graceful_stop_operation_id
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.predecessor_sha256 != exact_intent.sha256
            or evidence.get("intent_sha256") != exact_intent.sha256
            or evidence.get(f"{prefix}_sha256") != envelope.sha256
            or evidence.get(f"{prefix}_artifact_name") != file_name
            or evidence.get(f"{prefix}_artifact_path")
            != f"{artifact_directory_path}/{file_name}"
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire terminal record crossed its root, intent, or artifact"
            )
        authenticated = authenticate_retained_lifecycle_v2_wire(
            envelope.encoded,
            authority_manifest=self._authority_manifest,
            root=exact_root,
            request_intent=exact_intent,
        )
        try:
            basis = LifecycleV2CleanStopRequestBasis.from_root(exact_root)
            request = LifecycleV2CleanStopRequest.from_prefix(
                exact_root,
                basis,
                exact_intent,
            )
            proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof(authenticated)
            wire_evidence = LifecycleV2TerminalWireEvidence.capture(
                evidence,
                proof=proof,
                request=request,
                root=exact_root,
                responder_identity_sha256=exact_root.supervisor_process_epoch_sha256,
            )
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained terminal payload or evidence is not exact"
            ) from error
        if wire_evidence.to_dict() != evidence:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire evidence changed under terminal validation"
            )
        return authenticated

    def require_exact_authenticated_retained_terminal_wire(
        self,
        result: object,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        self._require_owner()
        if (
            type(result) is not AuthenticatedLifecycleV2TransportEnvelope
            or result._capability is not _AUTHENTICATED_VALUE_CAPABILITY
            or type(result.envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or result.authority_manifest_sha256
            != self._authority_manifest.manifest.sha256
            or result.signer_role != "supervisor"
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result is not its exact sealed value"
            )
        try:
            canonical = decode_unverified_lifecycle_v2_transport_envelope(
                result.envelope.encoded
            )
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result changed under validation"
            ) from error
        if canonical != result.envelope:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result changed under validation"
            )
        return result


def _build_injected_lifecycle_v2_ed25519_retained_wire_verifier(
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
) -> _LifecycleV2Ed25519RetainedWireVerifier:
    authenticated = _require_authenticated_manifest(authority_manifest)
    result = object.__new__(_LifecycleV2Ed25519RetainedWireVerifier)
    object.__setattr__(result, "_authority_manifest", authenticated)
    object.__setattr__(result, "_origin_pid", os.getpid())
    object.__setattr__(result, "_origin_thread", threading.current_thread())
    object.__setattr__(result, "_capability", _AUTHENTICATED_VALUE_CAPABILITY)
    result._require_owner()
    return result


def lifecycle_v2_ed25519_non_authority_facts() -> dict[str, bool]:
    return {
        "private_key_present": False,
        "key_loader_present": False,
        "installed_authority_reader_present": False,
        "socket_transport_present": False,
        "production_caller_present": False,
        "stop_effect_authorized": False,
    }


__all__ = [
    "TRANSPORT_ENVELOPE_MAXIMUM_OVERHEAD_BYTES",
    "AuthenticatedLifecycleV2Handshake",
    "AuthenticatedLifecycleV2RecoveryClassificationEnvelope",
    "AuthenticatedLifecycleV2TransportAuthority",
    "AuthenticatedLifecycleV2TransportAuthorityManifest",
    "AuthenticatedLifecycleV2TransportAuthoritySelection",
    "AuthenticatedLifecycleV2TransportEnvelope",
    "LifecycleV2TransportAuthenticationError",
    "authenticate_lifecycle_v2_recovery_classification_envelope",
    "authenticate_lifecycle_v2_transport_authority",
    "authenticate_lifecycle_v2_transport_authority_manifest",
    "authenticate_lifecycle_v2_transport_authority_selection",
    "authenticate_retained_lifecycle_v2_wire",
    "authenticate_root_bound_lifecycle_v2_transport_frame",
    "authenticate_selected_lifecycle_v2_handshake",
    "authenticated_lifecycle_v2_recovery_manifest_for_root",
    "bind_authenticated_lifecycle_v2_terminal_envelope_proof",
    "lifecycle_v2_ed25519_non_authority_facts",
]
