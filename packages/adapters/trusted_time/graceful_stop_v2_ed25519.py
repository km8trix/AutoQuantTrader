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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from cryptography.hazmat.bindings import _rust as _cryptography_rust

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_WIRE_MAXIMUM_BYTES,
    NORMAL_STAGE_BY_ORDINAL,
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
    LifecycleV2AuthenticatedRecoveryIntent,
    LifecycleV2RecoveryClassificationEnvelope,
    _consume_authenticated_lifecycle_v2_recovery_classification_envelope,
    _install_authenticated_lifecycle_v2_recovery_adapter_endpoint,
    decode_lifecycle_v2_recovery_classification_envelope,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    LifecycleV2AuthenticatedTerminalEnvelopeProof,
    LifecycleV2TerminalWireEvidence,
    _install_authenticated_terminal_envelope_adapter_endpoint,
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


class LifecycleV2TransportAuthenticationError(RuntimeError):
    """A signature or its exact admitted key/correlator binding failed closed."""


def _build_exact_ed25519_verification_endpoints() -> tuple[
    Callable[[object], object],
    Callable[[bytes, bytes, bytes], None],
]:
    """Anchor verification to the immutable compiled backend, not its public shim."""

    rust_binding = cast(Any, _cryptography_rust)
    primitive_module = cast(Any, rust_binding.openssl.ed25519)
    from_public_bytes = cast(Any, primitive_module.from_public_bytes)
    concrete_public_key_type = cast(Any, primitive_module.Ed25519PublicKey)
    verify_method = cast(Any, concrete_public_key_type.verify)
    builtin_function_type = type(len)
    method_descriptor_type = type(str.join)
    authentication_error_type = LifecycleV2TransportAuthenticationError
    exact_type = type
    bytes_type = bytes
    length = len
    exception_type = Exception
    type_error_type = TypeError
    cast_value = cast

    if (
        exact_type(from_public_bytes) is not builtin_function_type
        or exact_type(concrete_public_key_type) is not type
        or exact_type(verify_method) is not method_descriptor_type
        or getattr(verify_method, "__objclass__", None) is not concrete_public_key_type
        or getattr(verify_method, "__name__", None) != "verify"
    ):
        raise RuntimeError("compiled Ed25519 primitive provenance is invalid")

    def public_key(public_key_bytes: object) -> object:
        if exact_type(public_key_bytes) is not bytes_type:
            raise authentication_error_type(
                "transport authority public key must be exactly 32 bytes"
            )
        exact_public_key_bytes = cast_value("bytes", public_key_bytes)
        if length(exact_public_key_bytes) != 32:
            raise authentication_error_type(
                "transport authority public key must be exactly 32 bytes"
            )
        try:
            result = from_public_bytes(exact_public_key_bytes)
        except exception_type:
            raise authentication_error_type("transport authority public key is invalid") from None
        if exact_type(result) is not concrete_public_key_type:
            raise authentication_error_type("transport authority public key is invalid")
        return result

    def verify(public_key_bytes: bytes, signature_input: bytes, signature: bytes) -> None:
        try:
            if (
                exact_type(signature_input) is not bytes_type
                or exact_type(signature) is not bytes_type
            ):
                raise type_error_type("Ed25519 signature inputs are invalid")
            result = verify_method(public_key(public_key_bytes), signature, signature_input)
            if result is not None:
                raise type_error_type("Ed25519 verifier returned an invalid result")
        except authentication_error_type:
            raise
        except exception_type:
            raise authentication_error_type(
                "lifecycle-v2 Ed25519 signature authentication failed"
            ) from None

    known_public_key = bytes_type.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    known_signature = bytes_type.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    verify(known_public_key, b"", known_signature)
    try:
        verify(known_public_key, b"", bytes_type(64))
    except authentication_error_type:
        pass
    else:
        raise RuntimeError("compiled Ed25519 verifier failed its bootstrap self-test")

    return public_key, verify


_public_key, _verify = _build_exact_ed25519_verification_endpoints()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportAuthorityManifest:
    manifest: LifecycleV2TransportAuthorityManifest
    root_public_key_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated authority manifests require verification")


@dataclass(frozen=True, slots=True)
class _AuthenticatedManifestIssuanceSnapshot:
    value: AuthenticatedLifecycleV2TransportAuthorityManifest
    manifest_encoded: bytes
    root_public_key_sha256: str
    origin_pid: int
    origin_thread: threading.Thread


def _build_manifest_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportAuthorityManifest],
    Callable[[object], AuthenticatedLifecycleV2TransportAuthorityManifest],
]:
    """Keep manifest issuance authority inside the verifying endpoint closure."""

    authenticated_type = AuthenticatedLifecycleV2TransportAuthorityManifest
    manifest_type = LifecycleV2TransportAuthorityManifest
    snapshot_type = _AuthenticatedManifestIssuanceSnapshot
    decode_manifest = decode_lifecycle_v2_transport_authority_manifest
    verify_signature = _verify
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    exact_type = type
    exact_id = id
    bytes_type = bytes
    str_type = str
    new_object = object.__new__
    set_attribute = object.__setattr__
    sha256 = hashlib.sha256
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedManifestIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not authenticated_type
        ):
            raise authentication_error_type("transport authority manifest is not authenticated")
        try:
            canonical = decode_manifest(snapshot.manifest_encoded)
            value_manifest = value.manifest
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated transport authority manifest changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or exact_type(value_manifest) is not manifest_type
            or canonical.encoded != snapshot.manifest_encoded
            or value_manifest != canonical
            or value_manifest.encoded != snapshot.manifest_encoded
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise authentication_error_type(
                "authenticated transport authority manifest changed under validation"
            )
        return value

    def authenticate(
        encoded: object,
        *,
        reviewed_root_key_id: str,
        reviewed_root_public_key: bytes,
    ) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
        """Decode and authenticate one manifest under the injected offline root."""

        try:
            manifest = decode_manifest(encoded)
        except rejected_type as error:
            raise authentication_error_type(
                "transport authority manifest is not canonical"
            ) from error
        if (
            exact_type(reviewed_root_key_id) is not str_type
            or manifest.root_key_id != reviewed_root_key_id
        ):
            raise authentication_error_type(
                "transport authority manifest crossed the reviewed root identity"
            )
        public_key = (
            reviewed_root_public_key if exact_type(reviewed_root_public_key) is bytes_type else b""
        )
        if reviewed_root_key_id in {
            manifest.host_key_id,
            manifest.supervisor_key_id,
            manifest.recovery_key_id,
        } or public_key in {
            manifest.host_public_key,
            manifest.supervisor_public_key,
            manifest.recovery_public_key,
        }:
            raise authentication_error_type(
                "offline transport root identity cannot be reused by an endpoint role"
            )
        verify_signature(public_key, manifest.signature_input, manifest.signature)
        result = new_object(authenticated_type)
        root_digest = sha256(public_key).hexdigest()
        set_attribute(result, "manifest", manifest)
        set_attribute(result, "root_public_key_sha256", root_digest)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            manifest_encoded=manifest.encoded,
            root_public_key_sha256=root_digest,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "transport authority manifest identity was already authenticated"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    return authenticate, require


(
    authenticate_lifecycle_v2_transport_authority_manifest,
    _require_authenticated_manifest,
) = _build_manifest_authentication_endpoints()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportAuthoritySelection:
    selection: LifecycleV2TransportAuthoritySelection
    root_public_key_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated authority selections require verification")


@dataclass(frozen=True, slots=True)
class _AuthenticatedSelectionIssuanceSnapshot:
    value: AuthenticatedLifecycleV2TransportAuthoritySelection
    selection_encoded: bytes
    root_public_key_sha256: str
    origin_pid: int
    origin_thread: threading.Thread


def _build_selection_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportAuthoritySelection],
    Callable[[object], AuthenticatedLifecycleV2TransportAuthoritySelection],
]:
    """Keep selection issuance authority inside the verifying endpoint closure."""

    authenticated_type = AuthenticatedLifecycleV2TransportAuthoritySelection
    selection_type = LifecycleV2TransportAuthoritySelection
    snapshot_type = _AuthenticatedSelectionIssuanceSnapshot
    decode_selection = decode_lifecycle_v2_transport_authority_selection
    verify_signature = _verify
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    exact_type = type
    exact_id = id
    bytes_type = bytes
    new_object = object.__new__
    set_attribute = object.__setattr__
    sha256 = hashlib.sha256
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedSelectionIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not authenticated_type
        ):
            raise authentication_error_type("transport authority selection is not authenticated")
        try:
            canonical = decode_selection(snapshot.selection_encoded)
            value_selection = value.selection
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated transport authority selection changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or exact_type(value_selection) is not selection_type
            or canonical.encoded != snapshot.selection_encoded
            or value_selection != canonical
            or value_selection.encoded != snapshot.selection_encoded
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise authentication_error_type(
                "authenticated transport authority selection changed under validation"
            )
        return value

    def authenticate(
        encoded: object,
        *,
        reviewed_root_public_key: bytes,
    ) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
        """Decode and authenticate one selection under the injected offline root."""

        try:
            selection = decode_selection(encoded)
        except rejected_type as error:
            raise authentication_error_type(
                "transport authority selection is not canonical"
            ) from error
        public_key = (
            reviewed_root_public_key if exact_type(reviewed_root_public_key) is bytes_type else b""
        )
        verify_signature(public_key, selection.signature_input, selection.signature)
        result = new_object(authenticated_type)
        root_digest = sha256(public_key).hexdigest()
        set_attribute(result, "selection", selection)
        set_attribute(result, "root_public_key_sha256", root_digest)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            selection_encoded=selection.encoded,
            root_public_key_sha256=root_digest,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "transport authority selection identity was already authenticated"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    return authenticate, require


(
    authenticate_lifecycle_v2_transport_authority_selection,
    _require_authenticated_selection,
) = _build_selection_authentication_endpoints()


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
        for item in self.authenticated_manifests:
            if item.manifest.sha256 == selected.sha256:
                return item
        return None

    @property
    def recovery_manifest(self) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
        recovery = self.resolution.recovery_manifest
        if recovery is None:
            return None
        for item in self.authenticated_manifests:
            if item.manifest.sha256 == recovery.sha256:
                return item
        return None


@dataclass(frozen=True, slots=True)
class _AuthenticatedAuthorityIssuanceSnapshot:
    value: AuthenticatedLifecycleV2TransportAuthority
    manifest_encoded_chain: tuple[bytes, ...]
    selection_encoded_chain: tuple[bytes, ...]
    authenticated_manifests: tuple[AuthenticatedLifecycleV2TransportAuthorityManifest, ...]
    authenticated_selections: tuple[AuthenticatedLifecycleV2TransportAuthoritySelection, ...]
    root_public_key_sha256: str
    origin_pid: int
    origin_thread: threading.Thread


def _build_authority_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportAuthority],
    Callable[[object], AuthenticatedLifecycleV2TransportAuthority],
    Callable[
        [object],
        AuthenticatedLifecycleV2TransportAuthorityManifest | None,
    ],
]:
    """Keep resolved-chain issuance behind complete signature verification."""

    authenticated_type = AuthenticatedLifecycleV2TransportAuthority
    snapshot_type = _AuthenticatedAuthorityIssuanceSnapshot
    manifest_authenticate = authenticate_lifecycle_v2_transport_authority_manifest
    selection_authenticate = authenticate_lifecycle_v2_transport_authority_selection
    require_manifest = _require_authenticated_manifest
    require_selection = _require_authenticated_selection
    decode_manifest = decode_lifecycle_v2_transport_authority_manifest
    decode_selection = decode_lifecycle_v2_transport_authority_selection
    resolve_authority = resolve_lifecycle_v2_transport_authority
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    tuple_type = tuple
    any_value = any
    exact_type = type
    exact_id = id
    new_object = object.__new__
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedAuthorityIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthority:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not authenticated_type
        ):
            raise authentication_error_type("transport authority resolution is not authenticated")
        try:
            manifests = tuple_type(
                require_manifest(item) for item in snapshot.authenticated_manifests
            )
            selections = tuple_type(
                require_selection(item) for item in snapshot.authenticated_selections
            )
            canonical_manifests = tuple_type(
                decode_manifest(encoded) for encoded in snapshot.manifest_encoded_chain
            )
            canonical_selections = tuple_type(
                decode_selection(encoded) for encoded in snapshot.selection_encoded_chain
            )
            resolution = resolve_authority(
                canonical_manifests,
                canonical_selections,
            )
            value_resolution = value.resolution
            value_manifests = value.authenticated_manifests
            value_selections = value.authenticated_selections
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated transport authority changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_manifests is not snapshot.authenticated_manifests
            or value_selections is not snapshot.authenticated_selections
            or manifests != snapshot.authenticated_manifests
            or selections != snapshot.authenticated_selections
            or tuple_type(item.manifest for item in manifests) != canonical_manifests
            or tuple_type(item.selection for item in selections) != canonical_selections
            or value_resolution != resolution
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise authentication_error_type(
                "authenticated transport authority changed under validation"
            )
        return value

    def authenticate(
        manifest_encoded_chain: tuple[bytes, ...],
        selection_encoded_chain: tuple[bytes, ...],
        *,
        reviewed_root_key_id: str,
        reviewed_root_public_key: bytes,
    ) -> AuthenticatedLifecycleV2TransportAuthority:
        """Authenticate and structurally resolve complete manifest/selection chains."""

        manifests = tuple_type(
            manifest_authenticate(
                encoded,
                reviewed_root_key_id=reviewed_root_key_id,
                reviewed_root_public_key=reviewed_root_public_key,
            )
            for encoded in manifest_encoded_chain
        )
        selections = tuple_type(
            selection_authenticate(
                encoded,
                reviewed_root_public_key=reviewed_root_public_key,
            )
            for encoded in selection_encoded_chain
        )
        if not manifests or not selections:
            raise authentication_error_type("transport authority chains cannot be empty")
        root_digest = manifests[0].root_public_key_sha256
        if any_value(item.root_public_key_sha256 != root_digest for item in manifests) or any_value(
            item.root_public_key_sha256 != root_digest for item in selections
        ):
            raise authentication_error_type(
                "transport authority chain crossed the reviewed root key"
            )
        try:
            resolution = resolve_authority(
                tuple_type(item.manifest for item in manifests),
                tuple_type(item.selection for item in selections),
            )
        except rejected_type as error:
            raise authentication_error_type(
                "transport authority predecessor chain is invalid"
            ) from error
        result = new_object(authenticated_type)
        set_attribute(result, "resolution", resolution)
        set_attribute(result, "authenticated_manifests", manifests)
        set_attribute(result, "authenticated_selections", selections)
        set_attribute(result, "root_public_key_sha256", root_digest)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            manifest_encoded_chain=tuple_type(item.manifest.encoded for item in manifests),
            selection_encoded_chain=tuple_type(item.selection.encoded for item in selections),
            authenticated_manifests=manifests,
            authenticated_selections=selections,
            root_public_key_sha256=root_digest,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "transport authority identity was already authenticated"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    def selected_manifest(
        value: object,
    ) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
        authenticated = require(value)
        selected = authenticated.resolution.selected_manifest
        if selected is None:
            return None
        for item in authenticated.authenticated_manifests:
            exact_item = require_manifest(item)
            if exact_item.manifest.sha256 == selected.sha256:
                return exact_item
        raise authentication_error_type(
            "selected transport authority manifest lacks authenticated issuance"
        )

    return authenticate, require, selected_manifest


(
    authenticate_lifecycle_v2_transport_authority,
    _require_authenticated_authority,
    _selected_authenticated_lifecycle_v2_transport_manifest,
) = _build_authority_authentication_endpoints()


def _build_authenticated_recovery_manifest_selector() -> Callable[
    ...,
    AuthenticatedLifecycleV2TransportAuthorityManifest | None,
]:
    require_authority = _require_authenticated_authority
    require_manifest = _require_authenticated_manifest
    select_recovery = lifecycle_v2_recovery_manifest_for_root
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected

    def select(
        authority: AuthenticatedLifecycleV2TransportAuthority,
        *,
        root_manifest_sha256: object,
        root_generation: object,
    ) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
        """Return the authenticated recovery key only for an exact pinned root."""

        authenticated_authority = require_authority(authority)
        try:
            recovery = select_recovery(
                authenticated_authority.resolution,
                root_manifest_sha256=root_manifest_sha256,
                root_generation=root_generation,
            )
        except rejected_type as error:
            raise authentication_error_type("root-pinned recovery generation is invalid") from error
        if recovery is None:
            return None
        for item in authenticated_authority.authenticated_manifests:
            exact_item = require_manifest(item)
            if exact_item.manifest.sha256 == recovery.sha256:
                return exact_item
        raise authentication_error_type(
            "recovery transport authority manifest lacks authenticated issuance"
        )

    return select


authenticated_lifecycle_v2_recovery_manifest_for_root = (
    _build_authenticated_recovery_manifest_selector()
)


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
    envelope: LifecycleV2RecoveryClassificationEnvelope
    root_sha256: str
    classified_transcript_sha256: str
    authority_manifest_sha256: str
    _origin_pid: int
    _origin_thread: threading.Thread
    _consumed: bool
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated recovery classifications require verification")


@dataclass(frozen=True, slots=True)
class _AuthenticatedRecoveryClassificationIssuanceSnapshot:
    """Closure-owned immutable facts captured after Ed25519 verification."""

    value: AuthenticatedLifecycleV2RecoveryClassificationEnvelope
    envelope_encoded: bytes
    root_sha256: str
    classified_transcript_sha256: str
    authority_manifest_sha256: str
    origin_pid: int
    origin_thread: threading.Thread
    capability: object


def _authenticated_recovery_classification_issuance_registry(
    *,
    verify_envelope: Callable[
        ...,
        tuple[
            LifecycleV2RecoveryClassificationEnvelope,
            LifecycleV2Root,
            LifecycleV2Transcript,
            LifecycleV2TransportAuthorityManifest,
        ],
    ],
    require_issuance: Callable[
        [object, _AuthenticatedRecoveryClassificationIssuanceSnapshot],
        AuthenticatedLifecycleV2RecoveryClassificationEnvelope,
    ],
) -> tuple[
    Callable[..., AuthenticatedLifecycleV2RecoveryClassificationEnvelope],
    Callable[[object], AuthenticatedLifecycleV2RecoveryClassificationEnvelope],
    Callable[[object], tuple[LifecycleV2RecoveryClassificationEnvelope, str, str, str]],
]:
    authenticated_type = AuthenticatedLifecycleV2RecoveryClassificationEnvelope
    snapshot_type = _AuthenticatedRecoveryClassificationIssuanceSnapshot
    decode_envelope = decode_lifecycle_v2_recovery_classification_envelope
    authentication_error_type = LifecycleV2TransportAuthenticationError
    exact_id = id
    new_object = object.__new__
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedRecoveryClassificationIssuanceSnapshot] = {}
    consumed: set[int] = set()
    issuance_capability = object()
    lock = threading.Lock()

    def issue(
        value: AuthenticatedLifecycleV2RecoveryClassificationEnvelope,
        *,
        envelope_encoded: bytes,
        root_sha256: str,
        classified_transcript_sha256: str,
        authority_manifest_sha256: str,
    ) -> None:
        key = exact_id(value)
        snapshot = snapshot_type(
            value=value,
            envelope_encoded=envelope_encoded,
            root_sha256=root_sha256,
            classified_transcript_sha256=classified_transcript_sha256,
            authority_manifest_sha256=authority_manifest_sha256,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
            capability=issuance_capability,
        )
        with lock:
            if key in snapshots:
                raise authentication_error_type(
                    "recovery classification identity was already authenticated"
                )
            snapshots[key] = snapshot

    def lookup(
        value: object,
        *,
        consume: bool,
    ) -> _AuthenticatedRecoveryClassificationIssuanceSnapshot:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
            if snapshot is None or snapshot.value is not value:
                raise authentication_error_type(
                    "recovery classification has no exact authenticated issuance"
                )
            if consume:
                if (
                    get_pid() != snapshot.origin_pid
                    or current_thread() is not snapshot.origin_thread
                ):
                    raise authentication_error_type(
                        "authenticated recovery classification owner is invalid"
                    )
                if key in consumed:
                    raise authentication_error_type(
                        "authenticated recovery classification was already consumed"
                    )
                consumed.add(key)
            return snapshot

    def authenticate(
        encoded: object,
        *,
        authority: AuthenticatedLifecycleV2TransportAuthority,
        root: LifecycleV2Root,
        classified_transcript: LifecycleV2Transcript,
    ) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
        envelope, exact_root, exact_transcript, manifest = verify_envelope(
            encoded,
            authority=authority,
            root=root,
            classified_transcript=classified_transcript,
        )
        result = new_object(authenticated_type)
        set_attribute(result, "envelope", envelope)
        set_attribute(result, "root_sha256", exact_root.sha256)
        set_attribute(result, "classified_transcript_sha256", exact_transcript.sha256)
        set_attribute(result, "authority_manifest_sha256", manifest.sha256)
        set_attribute(result, "_origin_pid", get_pid())
        set_attribute(result, "_origin_thread", current_thread())
        set_attribute(result, "_consumed", False)
        set_attribute(result, "_capability", issuance_capability)
        issue(
            result,
            envelope_encoded=envelope.encoded,
            root_sha256=exact_root.sha256,
            classified_transcript_sha256=exact_transcript.sha256,
            authority_manifest_sha256=manifest.sha256,
        )
        return require(result)

    def require(value: object) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
        snapshot = lookup(value, consume=False)
        return require_issuance(value, snapshot)

    def consume_value(
        value: object,
    ) -> tuple[LifecycleV2RecoveryClassificationEnvelope, str, str, str]:
        snapshot = lookup(value, consume=True)
        authenticated = require_issuance(value, snapshot)
        set_attribute(authenticated, "_consumed", True)
        return (
            decode_envelope(snapshot.envelope_encoded),
            snapshot.root_sha256,
            snapshot.classified_transcript_sha256,
            snapshot.authority_manifest_sha256,
        )

    return authenticate, require, consume_value


def _build_recovery_classification_validation_endpoints() -> tuple[
    Callable[
        ...,
        tuple[
            LifecycleV2RecoveryClassificationEnvelope,
            LifecycleV2Root,
            LifecycleV2Transcript,
            LifecycleV2TransportAuthorityManifest,
        ],
    ],
    Callable[
        [object, _AuthenticatedRecoveryClassificationIssuanceSnapshot],
        AuthenticatedLifecycleV2RecoveryClassificationEnvelope,
    ],
]:
    authenticated_type = AuthenticatedLifecycleV2RecoveryClassificationEnvelope
    envelope_type = LifecycleV2RecoveryClassificationEnvelope
    decode_envelope = decode_lifecycle_v2_recovery_classification_envelope
    decode_root = decode_lifecycle_v2_root
    decode_transcript = decode_lifecycle_v2_transcript
    recovery_manifest_for_root = authenticated_lifecycle_v2_recovery_manifest_for_root
    verify_signature = _verify
    normal_stages = dict(enumerate(NORMAL_STAGE_BY_ORDINAL))
    error_retained_stage = LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    exact_type = type
    cast_value = cast
    attribute_error_type = AttributeError
    type_error_type = TypeError
    get_pid = os.getpid
    current_thread = threading.current_thread

    def require_issuance(
        value: object,
        snapshot: _AuthenticatedRecoveryClassificationIssuanceSnapshot,
    ) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
        if exact_type(value) is not authenticated_type:
            raise authentication_error_type("recovery classification is not authenticated")
        authenticated_value = cast_value(
            authenticated_type,
            value,
        )
        try:
            canonical = decode_envelope(snapshot.envelope_encoded)
            value_envelope = authenticated_value.envelope
            value_root_sha256 = authenticated_value.root_sha256
            value_transcript_sha256 = authenticated_value.classified_transcript_sha256
            value_manifest_sha256 = authenticated_value.authority_manifest_sha256
            value_origin_pid = authenticated_value._origin_pid
            value_origin_thread = authenticated_value._origin_thread
            value_consumed = authenticated_value._consumed
            value_capability = authenticated_value._capability
        except (attribute_error_type, type_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated recovery classification changed under validation"
            ) from error
        if (
            snapshot.value is not value
            or value_capability is not snapshot.capability
            or get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_origin_pid != snapshot.origin_pid
            or value_origin_thread is not snapshot.origin_thread
            or value_consumed is not False
            or canonical.encoded != snapshot.envelope_encoded
            or canonical.root_sha256 != snapshot.root_sha256
            or canonical.transcript_sha256 != snapshot.classified_transcript_sha256
            or canonical.transport_authority_manifest_sha256 != snapshot.authority_manifest_sha256
            or exact_type(value_envelope) is not envelope_type
            or value_envelope != canonical
            or value_envelope.encoded != snapshot.envelope_encoded
            or value_root_sha256 != snapshot.root_sha256
            or value_transcript_sha256 != snapshot.classified_transcript_sha256
            or value_manifest_sha256 != snapshot.authority_manifest_sha256
        ):
            raise authentication_error_type(
                "authenticated recovery classification changed under validation"
            )
        return authenticated_value

    def verify_envelope(
        encoded: object,
        *,
        authority: AuthenticatedLifecycleV2TransportAuthority,
        root: LifecycleV2Root,
        classified_transcript: LifecycleV2Transcript,
    ) -> tuple[
        LifecycleV2RecoveryClassificationEnvelope,
        LifecycleV2Root,
        LifecycleV2Transcript,
        LifecycleV2TransportAuthorityManifest,
    ]:
        """Verify exact recovery-classification inputs without minting authority."""

        try:
            envelope = decode_envelope(encoded)
            exact_root = decode_root(root.encoded)
            exact_transcript = decode_transcript(classified_transcript.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "recovery classification inputs are not canonical"
            ) from error
        if exact_root != root or exact_transcript != classified_transcript:
            raise authentication_error_type(
                "recovery classification inputs changed under validation"
            )
        for entry in exact_transcript.entries:
            expected_stage = normal_stages.get(entry.ordinal)
            if entry.ordinal == 2 and entry.stage is error_retained_stage:
                if entry is not exact_transcript.entries[-1]:
                    raise authentication_error_type(
                        "recovery classification crossed an impossible lifecycle prefix"
                    )
                continue
            if expected_stage is None or entry.stage is not expected_stage:
                raise authentication_error_type(
                    "recovery classification crossed an impossible lifecycle prefix"
                )
        recovery = recovery_manifest_for_root(
            authority,
            root_manifest_sha256=exact_root.transport_authority_manifest_sha256,
            root_generation=exact_root.transport_key_generation,
        )
        if recovery is None:
            raise authentication_error_type("root-pinned recovery classification is not selected")
        manifest = recovery.manifest
        if (
            manifest.sha256 != exact_root.transport_authority_manifest_sha256
            or manifest.generation != exact_root.transport_key_generation
            or manifest.environment != exact_root.environment
            or envelope.environment != exact_root.environment
            or envelope.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or envelope.root_sha256 != exact_root.sha256
            or envelope.admission_started_boottime_ns != exact_root.admission_started_boottime_ns
            or envelope.operation_deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or envelope.transcript_sha256 != exact_transcript.sha256
            or envelope.last_ordinal != exact_transcript.entries[-1].ordinal
            or envelope.last_stage is not exact_transcript.entries[-1].stage
            or exact_transcript.environment != exact_root.environment
            or exact_transcript.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or exact_transcript.root_sha256 != exact_root.sha256
            or envelope.transport_authority_manifest_sha256 != manifest.sha256
            or envelope.key_generation != manifest.generation
            or envelope.recovery_key_id != manifest.recovery_key_id
        ):
            raise authentication_error_type(
                "recovery classification crossed its root, prefix, or recovery generation"
            )
        verify_signature(
            manifest.recovery_public_key,
            envelope.signature_input,
            envelope.signature,
        )
        return envelope, exact_root, exact_transcript, manifest

    return verify_envelope, require_issuance


(
    _verify_lifecycle_v2_recovery_classification_envelope,
    _require_authenticated_recovery_classification_issuance,
) = _build_recovery_classification_validation_endpoints()

(
    authenticate_lifecycle_v2_recovery_classification_envelope,
    _require_authenticated_lifecycle_v2_recovery_classification_envelope,
    _consume_authenticated_lifecycle_v2_recovery_envelope_value,
) = _authenticated_recovery_classification_issuance_registry(
    verify_envelope=_verify_lifecycle_v2_recovery_classification_envelope,
    require_issuance=_require_authenticated_recovery_classification_issuance,
)

_install_authenticated_lifecycle_v2_recovery_adapter_endpoint(
    _consume_authenticated_lifecycle_v2_recovery_envelope_value
)


def _build_authenticated_recovery_classification_consumer() -> Callable[
    ...,
    LifecycleV2AuthenticatedRecoveryIntent,
]:
    consume_envelope = _consume_authenticated_lifecycle_v2_recovery_classification_envelope

    def consume(
        authenticated_envelope: object,
        *,
        root: LifecycleV2Root,
        classified_transcript: LifecycleV2Transcript,
        recorded_at_utc: str,
    ) -> LifecycleV2AuthenticatedRecoveryIntent:
        """Consume one authenticated classifier into its exact durable intent."""

        return consume_envelope(
            authenticated_envelope,
            root=root,
            classified_transcript=classified_transcript,
            recorded_at_utc=recorded_at_utc,
        )

    return consume


consume_authenticated_lifecycle_v2_recovery_classification_envelope = (
    _build_authenticated_recovery_classification_consumer()
)


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2Handshake:
    handshake: LifecycleV2Handshake
    authority_manifest_sha256: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated handshakes require signature verification")


def _build_exact_lifecycle_v2_handshake_verifier() -> Callable[
    ...,
    tuple[LifecycleV2Handshake, str],
]:
    require_manifest = _require_authenticated_manifest
    decode_host = decode_lifecycle_v2_host_hello
    decode_supervisor = decode_lifecycle_v2_supervisor_hello
    decode_confirmation = decode_lifecycle_v2_host_channel_confirmation
    bind_handshake = bind_lifecycle_v2_handshake
    verify_signature = _verify
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected

    def require_correlators(
        manifest: LifecycleV2TransportAuthorityManifest,
        fields: dict[str, object],
    ) -> None:
        if (
            fields["environment"] != manifest.environment
            or fields["transport_authority_manifest_sha256"] != manifest.sha256
            or fields["key_generation"] != manifest.generation
            or fields["host_key_id"] != manifest.host_key_id
        ):
            raise authentication_error_type(
                "handshake crossed its authenticated authority manifest"
            )

    def verify_handshake(
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        *,
        host_hello_encoded: bytes,
        supervisor_hello_encoded: bytes,
        host_confirmation_encoded: bytes,
    ) -> tuple[LifecycleV2Handshake, str]:
        """Verify and correlate the exact three-message mutual handshake."""

        authenticated = require_manifest(authority_manifest)
        manifest = authenticated.manifest
        try:
            host = decode_host(host_hello_encoded)
            supervisor = decode_supervisor(supervisor_hello_encoded)
            confirmation = decode_confirmation(host_confirmation_encoded)
        except rejected_type as error:
            raise authentication_error_type(
                "lifecycle-v2 handshake message is not canonical"
            ) from error
        require_correlators(manifest, host.to_dict())
        require_correlators(manifest, supervisor.to_dict())
        require_correlators(manifest, confirmation.to_dict())
        if (
            host.to_dict()["expected_supervisor_key_id"] != manifest.supervisor_key_id
            or supervisor.to_dict()["supervisor_key_id"] != manifest.supervisor_key_id
            or confirmation.to_dict()["supervisor_key_id"] != manifest.supervisor_key_id
        ):
            raise authentication_error_type("handshake crossed the authenticated supervisor key")
        verify_signature(manifest.host_public_key, host.signature_input, host.signature)
        verify_signature(
            manifest.supervisor_public_key,
            supervisor.signature_input,
            supervisor.signature,
        )
        verify_signature(
            manifest.host_public_key,
            confirmation.signature_input,
            confirmation.signature,
        )
        try:
            handshake = bind_handshake(host, supervisor, confirmation)
        except rejected_type as error:
            raise authentication_error_type(
                "authenticated handshake correlators disagree"
            ) from error
        return handshake, manifest.sha256

    return verify_handshake


_verify_lifecycle_v2_handshake = _build_exact_lifecycle_v2_handshake_verifier()


@dataclass(frozen=True, slots=True)
class _AuthenticatedHandshakeIssuanceSnapshot:
    value: AuthenticatedLifecycleV2Handshake
    host_hello_encoded: bytes
    supervisor_hello_encoded: bytes
    host_confirmation_encoded: bytes
    authority_manifest_sha256: str
    origin_pid: int
    origin_thread: threading.Thread


def _build_handshake_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2Handshake],
    Callable[[object], AuthenticatedLifecycleV2Handshake],
]:
    authenticated_type = AuthenticatedLifecycleV2Handshake
    snapshot_type = _AuthenticatedHandshakeIssuanceSnapshot
    require_authority = _require_authenticated_authority
    selected_manifest = _selected_authenticated_lifecycle_v2_transport_manifest
    verify_handshake = _verify_lifecycle_v2_handshake
    bind_handshake = bind_lifecycle_v2_handshake
    decode_host = decode_lifecycle_v2_host_hello
    decode_supervisor = decode_lifecycle_v2_supervisor_hello
    decode_confirmation = decode_lifecycle_v2_host_channel_confirmation
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    exact_type = type
    exact_id = id
    new_object = object.__new__
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedHandshakeIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2Handshake:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not authenticated_type
        ):
            raise authentication_error_type("lifecycle-v2 handshake is not authenticated")
        try:
            canonical_handshake = bind_handshake(
                decode_host(snapshot.host_hello_encoded),
                decode_supervisor(snapshot.supervisor_hello_encoded),
                decode_confirmation(snapshot.host_confirmation_encoded),
            )
            value_handshake = value.handshake
            value_manifest_sha256 = value.authority_manifest_sha256
            value_capability = value._capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated lifecycle-v2 handshake changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_handshake != canonical_handshake
            or value_manifest_sha256 != snapshot.authority_manifest_sha256
        ):
            raise authentication_error_type(
                "authenticated lifecycle-v2 handshake changed under validation"
            )
        return value

    def authenticate(
        authority: AuthenticatedLifecycleV2TransportAuthority,
        *,
        host_hello_encoded: bytes,
        supervisor_hello_encoded: bytes,
        host_confirmation_encoded: bytes,
    ) -> AuthenticatedLifecycleV2Handshake:
        """Authenticate a new-root handshake only when current selection permits it."""

        authenticated_authority = require_authority(authority)
        selected = selected_manifest(authenticated_authority)
        if selected is None:
            raise authentication_error_type(
                "current transport authority selection denies new roots"
            )
        handshake, manifest_sha256 = verify_handshake(
            selected,
            host_hello_encoded=host_hello_encoded,
            supervisor_hello_encoded=supervisor_hello_encoded,
            host_confirmation_encoded=host_confirmation_encoded,
        )
        result = new_object(authenticated_type)
        set_attribute(result, "handshake", handshake)
        set_attribute(result, "authority_manifest_sha256", manifest_sha256)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            host_hello_encoded=handshake.host_hello.encoded,
            supervisor_hello_encoded=handshake.supervisor_hello.encoded,
            host_confirmation_encoded=handshake.host_confirmation.encoded,
            authority_manifest_sha256=manifest_sha256,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "lifecycle-v2 handshake identity was already authenticated"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    return authenticate, require


(
    authenticate_selected_lifecycle_v2_handshake,
    _require_authenticated_lifecycle_v2_handshake,
) = _build_handshake_authentication_endpoints()


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
        raise TypeError("transport frame expectation requires runtime installation")


@dataclass(frozen=True, slots=True)
class _TransportFrameExpectationIssuanceSnapshot:
    value: _LifecycleV2TransportFrameExpectation
    fields: tuple[object, ...]
    origin_pid: int
    origin_thread: threading.Thread


_EXPECTATION_FIELD_NAMES = (
    "environment",
    "transport_authority_manifest_sha256",
    "frame_type",
    "key_generation",
    "signing_key_id",
    "boot_epoch_sha256",
    "host_process_epoch_sha256",
    "supervisor_process_epoch_sha256",
    "channel_id",
    "lifecycle_dispatch_prefix_sha256",
    "message_counter",
    "deadline_boottime_ns",
)


def _build_transport_frame_expectation_endpoints() -> tuple[
    Callable[..., _LifecycleV2TransportFrameExpectation],
    Callable[[object], _LifecycleV2TransportFrameExpectation],
]:
    expectation_type = _LifecycleV2TransportFrameExpectation
    snapshot_type = _TransportFrameExpectationIssuanceSnapshot
    field_names = tuple(_EXPECTATION_FIELD_NAMES)
    decode_root = decode_lifecycle_v2_root
    decode_progress = decode_lifecycle_v2_progress_record
    dispatch_prefix_sha256 = lifecycle_v2_dispatch_prefix_sha256
    request_intent_stage = LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    exact_type = type
    exact_id = id
    tuple_type = tuple
    get_attribute = getattr
    strict_zip = zip
    attribute_error_type = AttributeError
    new_object = object.__new__
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _TransportFrameExpectationIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> _LifecycleV2TransportFrameExpectation:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not expectation_type
        ):
            raise authentication_error_type("transport frame expectation has no exact issuance")
        try:
            fields = tuple_type(get_attribute(value, name) for name in field_names)
            capability = value._capability
        except attribute_error_type as error:
            raise authentication_error_type(
                "transport frame expectation changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or capability is not issuance_capability
            or fields != snapshot.fields
        ):
            raise authentication_error_type("transport frame expectation changed under validation")
        return value

    def derive(
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        *,
        frame_type: str,
    ) -> _LifecycleV2TransportFrameExpectation:
        try:
            exact_root = decode_root(root.encoded)
            exact_intent = decode_progress(request_intent.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "retained-wire expectation requires canonical root and intent"
            ) from error
        if (
            exact_root != root
            or exact_intent != request_intent
            or exact_intent.ordinal != 1
            or exact_intent.stage is not request_intent_stage
            or exact_intent.root_sha256 != exact_root.sha256
            or exact_intent.predecessor_sha256 != exact_root.sha256
            or frame_type not in {"clean_stop_request", "clean_stop_result", "clean_stop_error"}
        ):
            raise authentication_error_type(
                "retained-wire expectation does not bind the ordinal-one prefix"
            )
        host_frame = frame_type == "clean_stop_request"
        result = new_object(expectation_type)
        fields = (
            exact_root.environment,
            exact_root.transport_authority_manifest_sha256,
            frame_type,
            exact_root.transport_key_generation,
            (
                exact_root.host_transport_key_id
                if host_frame
                else exact_root.supervisor_transport_key_id
            ),
            exact_root.boot_epoch_sha256,
            exact_root.host_process_epoch_sha256,
            exact_root.supervisor_process_epoch_sha256,
            exact_root.channel_id,
            dispatch_prefix_sha256(exact_root, exact_intent),
            2 if host_frame else 1,
            exact_root.clean_stop_result_deadline_boottime_ns,
        )
        for name, value in strict_zip(field_names, fields, strict=True):
            set_attribute(result, name, value)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            fields=fields,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "transport frame expectation identity was already issued"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    return derive, require


(
    _derive_lifecycle_v2_transport_frame_expectation,
    _require_lifecycle_v2_transport_frame_expectation,
) = _build_transport_frame_expectation_endpoints()


def _build_transport_frame_expectation_classmethod(
    derive: Callable[..., _LifecycleV2TransportFrameExpectation],
) -> Callable[..., _LifecycleV2TransportFrameExpectation]:
    def from_root_and_intent(
        _cls: type[_LifecycleV2TransportFrameExpectation],
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        *,
        frame_type: str,
    ) -> _LifecycleV2TransportFrameExpectation:
        return derive(root, request_intent, frame_type=frame_type)

    return from_root_and_intent


type.__setattr__(
    _LifecycleV2TransportFrameExpectation,
    "from_root_and_intent",
    classmethod(
        _build_transport_frame_expectation_classmethod(
            _derive_lifecycle_v2_transport_frame_expectation
        )
    ),
)


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedLifecycleV2TransportEnvelope:
    envelope: UnverifiedLifecycleV2TransportEnvelope
    authority_manifest_sha256: str
    signer_role: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated transport envelopes require signature verification")


@dataclass(frozen=True, slots=True)
class _AuthenticatedTransportEnvelopeIssuanceSnapshot:
    value: AuthenticatedLifecycleV2TransportEnvelope
    envelope_encoded: bytes
    authority_manifest_sha256: str
    signer_role: str
    origin_pid: int
    origin_thread: threading.Thread


def _build_exact_transport_frame_validation_endpoints() -> tuple[
    Callable[[UnverifiedLifecycleV2TransportEnvelope], bytes],
    Callable[[UnverifiedLifecycleV2TransportEnvelope], None],
    Callable[..., tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]],
]:
    require_manifest = _require_authenticated_manifest
    require_expectation = _require_lifecycle_v2_transport_frame_expectation
    decode_envelope = decode_unverified_lifecycle_v2_transport_envelope
    canonical_json = canonical_v2_json_bytes
    verify_signature = _verify
    signature_domain = TRANSPORT_ENVELOPE_SIGNATURE_DOMAIN.encode("ascii")
    maximum_wire_bytes = LIFECYCLE_V2_WIRE_MAXIMUM_BYTES
    maximum_overhead_bytes = TRANSPORT_ENVELOPE_MAXIMUM_OVERHEAD_BYTES
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    exact_type = type
    str_type = str
    length = len
    any_value = any

    def signature_input(envelope: UnverifiedLifecycleV2TransportEnvelope) -> bytes:
        fields = envelope.to_dict()
        fields.pop("signature_ed25519_base64")
        unsigned = canonical_json(fields, maximum_bytes=maximum_wire_bytes)
        return signature_domain + b"\0" + unsigned

    def validate_formula(envelope: UnverifiedLifecycleV2TransportEnvelope) -> None:
        fields = envelope.to_dict()
        payload_base64 = fields["payload_base64"]
        if exact_type(payload_base64) is not str_type:
            raise authentication_error_type("transport payload encoding is invalid")
        exact_payload_base64 = str_type(payload_base64)
        fields["payload_base64"] = ""
        overhead = length(canonical_json(fields, maximum_bytes=maximum_wire_bytes))
        expected_payload_base64_length = 4 * ((length(envelope.payload) + 2) // 3)
        if (
            overhead > maximum_overhead_bytes
            or length(exact_payload_base64) != expected_payload_base64_length
            or length(envelope.encoded) != overhead + expected_payload_base64_length
        ):
            raise authentication_error_type(
                "transport envelope overhead or base64 length formula is invalid"
            )

    def verify_frame(
        encoded: object,
        *,
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        expectation: _LifecycleV2TransportFrameExpectation,
    ) -> tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]:
        """Verify one request, result, or error against exact correlators."""

        authenticated = require_manifest(authority_manifest)
        exact_expectation = require_expectation(expectation)
        try:
            envelope = decode_envelope(encoded)
        except rejected_type as error:
            raise authentication_error_type(
                "transport envelope is not structurally canonical"
            ) from error
        validate_formula(envelope)
        fields = envelope.to_dict()
        expected_fields: dict[str, object] = {
            "environment": exact_expectation.environment,
            "frame_type": exact_expectation.frame_type,
            "key_generation": exact_expectation.key_generation,
            "signing_key_id": exact_expectation.signing_key_id,
            "boot_epoch_sha256": exact_expectation.boot_epoch_sha256,
            "host_process_epoch_sha256": exact_expectation.host_process_epoch_sha256,
            "supervisor_process_epoch_sha256": exact_expectation.supervisor_process_epoch_sha256,
            "channel_id": exact_expectation.channel_id,
            "lifecycle_dispatch_prefix_sha256": exact_expectation.lifecycle_dispatch_prefix_sha256,
            "message_counter": exact_expectation.message_counter,
            "deadline_boottime_ns": exact_expectation.deadline_boottime_ns,
        }
        if any_value(fields[name] != expected for name, expected in expected_fields.items()):
            raise authentication_error_type(
                "transport envelope crossed an expected retained-wire correlator"
            )
        manifest = authenticated.manifest
        if (
            manifest.sha256 != exact_expectation.transport_authority_manifest_sha256
            or manifest.environment != exact_expectation.environment
            or manifest.generation != exact_expectation.key_generation
        ):
            raise authentication_error_type(
                "transport frame crossed its authenticated authority generation"
            )
        if exact_expectation.frame_type == "clean_stop_request":
            public_key = manifest.host_public_key
            expected_key_id = manifest.host_key_id
            signer_role = "host"
        else:
            public_key = manifest.supervisor_public_key
            expected_key_id = manifest.supervisor_key_id
            signer_role = "supervisor"
        if exact_expectation.signing_key_id != expected_key_id:
            raise authentication_error_type("transport frame crossed its authenticated signer role")
        verify_signature(public_key, signature_input(envelope), envelope.signature)
        return envelope, manifest.sha256, signer_role

    return signature_input, validate_formula, verify_frame


(
    _transport_envelope_signature_input,
    _validate_transport_envelope_formula,
    _verify_lifecycle_v2_transport_frame,
) = _build_exact_transport_frame_validation_endpoints()


def _build_transport_frame_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportEnvelope],
    Callable[[object], AuthenticatedLifecycleV2TransportEnvelope],
]:
    authenticated_type = AuthenticatedLifecycleV2TransportEnvelope
    envelope_type = UnverifiedLifecycleV2TransportEnvelope
    snapshot_type = _AuthenticatedTransportEnvelopeIssuanceSnapshot
    verify_frame = _verify_lifecycle_v2_transport_frame
    decode_envelope = decode_unverified_lifecycle_v2_transport_envelope
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    exact_type = type
    exact_id = id
    new_object = object.__new__
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    snapshots: dict[int, _AuthenticatedTransportEnvelopeIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportEnvelope:
        key = exact_id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not authenticated_type
        ):
            raise authentication_error_type(
                "transport envelope has no exact authenticated issuance"
            )
        try:
            canonical = decode_envelope(snapshot.envelope_encoded)
            value_envelope = value.envelope
            value_manifest_sha256 = value.authority_manifest_sha256
            value_signer_role = value.signer_role
            value_capability = value._capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "authenticated transport envelope changed under validation"
            ) from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or exact_type(value_envelope) is not envelope_type
            or canonical.encoded != snapshot.envelope_encoded
            or value_envelope != canonical
            or value_envelope.encoded != snapshot.envelope_encoded
            or value_manifest_sha256 != snapshot.authority_manifest_sha256
            or value_signer_role != snapshot.signer_role
        ):
            raise authentication_error_type(
                "authenticated transport envelope changed under validation"
            )
        return value

    def authenticate(
        encoded: object,
        *,
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        expectation: _LifecycleV2TransportFrameExpectation,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        envelope, manifest_sha256, signer_role = verify_frame(
            encoded,
            authority_manifest=authority_manifest,
            expectation=expectation,
        )
        result = new_object(authenticated_type)
        set_attribute(result, "envelope", envelope)
        set_attribute(result, "authority_manifest_sha256", manifest_sha256)
        set_attribute(result, "signer_role", signer_role)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = snapshot_type(
            value=result,
            envelope_encoded=envelope.encoded,
            authority_manifest_sha256=manifest_sha256,
            signer_role=signer_role,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in snapshots:
                raise authentication_error_type(
                    "transport envelope identity was already authenticated"
                )
            snapshots[exact_id(result)] = snapshot
        return require(result)

    return authenticate, require


(
    _authenticate_lifecycle_v2_transport_frame,
    _require_authenticated_lifecycle_v2_transport_envelope,
) = _build_transport_frame_authentication_endpoints()


def _build_authenticated_transport_envelope_unwrapper(
    require_endpoint: Callable[[object], AuthenticatedLifecycleV2TransportEnvelope],
) -> Callable[[object], tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]]:
    """Capture the registry validator so module-global replacement cannot redirect it."""

    def unwrap(
        value: object,
    ) -> tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]:
        authenticated = require_endpoint(value)
        return (
            authenticated.envelope,
            authenticated.authority_manifest_sha256,
            authenticated.signer_role,
        )

    return unwrap


_unwrap_authenticated_lifecycle_v2_transport_envelope = (
    _build_authenticated_transport_envelope_unwrapper(
        _require_authenticated_lifecycle_v2_transport_envelope
    )
)
_install_authenticated_terminal_envelope_adapter_endpoint(
    _unwrap_authenticated_lifecycle_v2_transport_envelope
)


def _build_terminal_proof_binder() -> Callable[
    [object],
    LifecycleV2AuthenticatedTerminalEnvelopeProof,
]:
    mint_proof = _mint_authenticated_lifecycle_v2_terminal_envelope_proof

    def bind(
        authenticated_envelope: object,
    ) -> LifecycleV2AuthenticatedTerminalEnvelopeProof:
        """Cross the reviewed adapter-to-domain seam for one authenticated terminal frame."""

        return mint_proof(authenticated_envelope)

    return bind


bind_authenticated_lifecycle_v2_terminal_envelope_proof = _build_terminal_proof_binder()


def _build_root_bound_transport_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportEnvelope],
    Callable[..., AuthenticatedLifecycleV2TransportEnvelope],
]:
    authenticate_frame = _authenticate_lifecycle_v2_transport_frame
    derive_expectation = _derive_lifecycle_v2_transport_frame_expectation
    require_manifest = _require_authenticated_manifest
    decode_envelope = decode_unverified_lifecycle_v2_transport_envelope
    decode_root = decode_lifecycle_v2_root
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError

    def authenticate_root_bound(
        encoded: object,
        *,
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        """Authenticate a frame against its exact durable-prefix correlators."""

        try:
            envelope = decode_envelope(encoded)
            exact_root = decode_root(root.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "root-bound lifecycle-v2 frame inputs are not canonical"
            ) from error
        expectation = derive_expectation(
            exact_root,
            request_intent,
            frame_type=envelope.frame_type,
        )
        return authenticate_frame(
            encoded,
            authority_manifest=authority_manifest,
            expectation=expectation,
        )

    def authenticate_retained(
        encoded: object,
        *,
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        """Reauthenticate retained result/error from root-pinned authority facts."""

        authenticated = require_manifest(authority_manifest)
        try:
            envelope = decode_envelope(encoded)
            exact_root = decode_root(root.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "retained lifecycle-v2 wire inputs are not canonical"
            ) from error
        if envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}:
            raise authentication_error_type(
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
            raise authentication_error_type(
                "retained root crossed its root-pinned transport authority"
            )
        expectation = derive_expectation(
            exact_root,
            request_intent,
            frame_type=envelope.frame_type,
        )
        return authenticate_frame(
            encoded,
            authority_manifest=authenticated,
            expectation=expectation,
        )

    return authenticate_root_bound, authenticate_retained


(
    authenticate_root_bound_lifecycle_v2_transport_frame,
    authenticate_retained_lifecycle_v2_wire,
) = _build_root_bound_transport_authentication_endpoints()


@dataclass(frozen=True, slots=True, init=False)
class _LifecycleV2Ed25519RetainedWireResult:
    """One exact terminal-wire proof sealed to its producing verifier."""

    envelope: UnverifiedLifecycleV2TransportEnvelope
    authority_manifest_sha256: str
    signer_role: str
    root_sha256: str
    request_intent_sha256: str
    terminal_record_sha256: str
    artifact_directory_path: str
    _verifier_capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("retained-wire results require verifier-owned authentication")


@dataclass(frozen=True, slots=True, init=False)
class _LifecycleV2Ed25519RetainedWireVerifier:
    """Process/thread-bound injected repository verifier over one public key."""

    _authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest
    _origin_pid: int
    _origin_thread: threading.Thread
    _sealed_result_capability: object
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("retained-wire verifiers require authenticated construction")

    def _require_owner(self) -> None:
        raise TypeError("retained-wire verifier methods require runtime installation")

    def reauthenticate_retained_terminal_wire(
        self,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        raise TypeError("retained-wire verifier methods require runtime installation")

    def require_exact_authenticated_retained_terminal_wire(
        self,
        result: object,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        raise TypeError("retained-wire verifier methods require runtime installation")


@dataclass(frozen=True, slots=True)
class _RetainedWireVerifierIssuanceSnapshot:
    value: _LifecycleV2Ed25519RetainedWireVerifier
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest
    authority_manifest_encoded: bytes
    sealed_result_capability: object
    origin_pid: int
    origin_thread: threading.Thread


@dataclass(frozen=True, slots=True)
class _RetainedWireResultIssuanceSnapshot:
    value: _LifecycleV2Ed25519RetainedWireResult
    verifier: _LifecycleV2Ed25519RetainedWireVerifier
    envelope_encoded: bytes
    authority_manifest_sha256: str
    signer_role: str
    root_sha256: str
    request_intent_sha256: str
    terminal_record_sha256: str
    artifact_directory_path: str
    verifier_capability: object


def _build_retained_wire_verifier_endpoints() -> tuple[
    Callable[..., _LifecycleV2Ed25519RetainedWireVerifier],
    Callable[[object], _LifecycleV2Ed25519RetainedWireVerifier],
    Callable[..., _LifecycleV2Ed25519RetainedWireResult],
    Callable[..., _LifecycleV2Ed25519RetainedWireResult],
    Callable[..., _LifecycleV2Ed25519RetainedWireResult],
]:
    verifier_type = _LifecycleV2Ed25519RetainedWireVerifier
    result_type = _LifecycleV2Ed25519RetainedWireResult
    verifier_snapshot_type = _RetainedWireVerifierIssuanceSnapshot
    result_snapshot_type = _RetainedWireResultIssuanceSnapshot
    envelope_type = UnverifiedLifecycleV2TransportEnvelope
    require_manifest = _require_authenticated_manifest
    require_authenticated_envelope = _require_authenticated_lifecycle_v2_transport_envelope
    authenticate_retained_wire = authenticate_retained_lifecycle_v2_wire
    decode_envelope = decode_unverified_lifecycle_v2_transport_envelope
    decode_root = decode_lifecycle_v2_root
    decode_progress = decode_lifecycle_v2_progress_record
    wire_file_name = lifecycle_v2_wire_file_name
    request_basis_from_root = LifecycleV2CleanStopRequestBasis.from_root
    request_from_prefix = LifecycleV2CleanStopRequest.from_prefix
    bind_terminal_proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof
    capture_wire_evidence = LifecycleV2TerminalWireEvidence.capture
    result_retained_stage = LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
    error_retained_stage = LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED
    authentication_error_type = LifecycleV2TransportAuthenticationError
    rejected_type = TrustedTimeGracefulStopV2Rejected
    attribute_error_type = AttributeError
    exact_type = type
    exact_id = id
    str_type = str
    new_object = object.__new__
    new_capability = object
    set_attribute = object.__setattr__
    get_pid = os.getpid
    current_thread = threading.current_thread
    verifier_snapshots: dict[int, _RetainedWireVerifierIssuanceSnapshot] = {}
    result_snapshots: dict[int, _RetainedWireResultIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require_verifier(value: object) -> _LifecycleV2Ed25519RetainedWireVerifier:
        key = exact_id(value)
        with lock:
            snapshot = verifier_snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or exact_type(value) is not verifier_type
        ):
            raise authentication_error_type("retained-wire verifier owner is invalid")
        try:
            authenticated_manifest = require_manifest(snapshot.authority_manifest)
            value_manifest = value._authority_manifest
            value_pid = value._origin_pid
            value_thread = value._origin_thread
            value_result_capability = value._sealed_result_capability
            value_capability = value._capability
        except attribute_error_type as error:
            raise authentication_error_type("retained-wire verifier owner is invalid") from error
        if (
            get_pid() != snapshot.origin_pid
            or current_thread() is not snapshot.origin_thread
            or value_pid != snapshot.origin_pid
            or value_thread is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_manifest is not snapshot.authority_manifest
            or authenticated_manifest.manifest.encoded != snapshot.authority_manifest_encoded
            or value_result_capability is not snapshot.sealed_result_capability
        ):
            raise authentication_error_type("retained-wire verifier owner is invalid")
        return value

    def build(
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    ) -> _LifecycleV2Ed25519RetainedWireVerifier:
        authenticated = require_manifest(authority_manifest)
        result = new_object(verifier_type)
        result_capability = new_capability()
        set_attribute(result, "_authority_manifest", authenticated)
        set_attribute(result, "_origin_pid", get_pid())
        set_attribute(result, "_origin_thread", current_thread())
        set_attribute(result, "_sealed_result_capability", result_capability)
        set_attribute(result, "_capability", issuance_capability)
        snapshot = verifier_snapshot_type(
            value=result,
            authority_manifest=authenticated,
            authority_manifest_encoded=authenticated.manifest.encoded,
            sealed_result_capability=result_capability,
            origin_pid=get_pid(),
            origin_thread=current_thread(),
        )
        with lock:
            if exact_id(result) in verifier_snapshots:
                raise authentication_error_type(
                    "retained-wire verifier identity was already issued"
                )
            verifier_snapshots[exact_id(result)] = snapshot
        return require_verifier(result)

    def seal_result(
        verifier: object,
        *,
        authenticated: AuthenticatedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        exact_verifier = require_verifier(verifier)
        exact_authenticated = require_authenticated_envelope(authenticated)
        try:
            exact_root = decode_root(root.encoded)
            exact_intent = decode_progress(request_intent.encoded)
            exact_record = decode_progress(terminal_record.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "retained-wire result inputs are not canonical"
            ) from error
        envelope = exact_authenticated.envelope
        prefix = (
            "clean_stop_result"
            if envelope.frame_type == "clean_stop_result"
            else "clean_stop_error"
        )
        expected_stage = (
            result_retained_stage
            if envelope.frame_type == "clean_stop_result"
            else error_retained_stage
        )
        evidence = exact_record.evidence.to_dict()
        file_name = wire_file_name(envelope)
        if (
            exact_root != root
            or exact_intent != request_intent
            or exact_record != terminal_record
            or envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}
            or exact_authenticated.authority_manifest_sha256
            != exact_verifier._authority_manifest.manifest.sha256
            or exact_authenticated.signer_role != "supervisor"
            or exact_record.ordinal != 2
            or exact_record.stage is not expected_stage
            or exact_record.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.predecessor_sha256 != exact_intent.sha256
            or exact_record.effect_kind != prefix
            or exact_record.deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or evidence.get("intent_sha256") != exact_intent.sha256
            or evidence.get(f"{prefix}_sha256") != envelope.sha256
            or evidence.get(f"{prefix}_artifact_name") != file_name
            or evidence.get(f"{prefix}_artifact_path") != f"{artifact_directory_path}/{file_name}"
        ):
            raise authentication_error_type(
                "retained-wire result crossed its verifier, root, intent, or artifact"
            )
        try:
            request = request_from_prefix(
                exact_root,
                request_basis_from_root(exact_root),
                exact_intent,
            )
            proof = bind_terminal_proof(exact_authenticated)
            wire_evidence = capture_wire_evidence(
                evidence,
                proof=proof,
                request=request,
                root=exact_root,
                responder_identity_sha256=exact_root.supervisor_process_epoch_sha256,
            )
        except rejected_type as error:
            raise authentication_error_type(
                "retained-wire result terminal evidence is not exact"
            ) from error
        if wire_evidence.to_dict() != evidence:
            raise authentication_error_type("retained-wire result terminal evidence changed")
        result = new_object(result_type)
        values: dict[str, object] = {
            "envelope": envelope,
            "authority_manifest_sha256": exact_authenticated.authority_manifest_sha256,
            "signer_role": exact_authenticated.signer_role,
            "root_sha256": exact_root.sha256,
            "request_intent_sha256": exact_intent.sha256,
            "terminal_record_sha256": exact_record.sha256,
            "artifact_directory_path": artifact_directory_path,
            "_verifier_capability": exact_verifier._sealed_result_capability,
        }
        for name, value in values.items():
            set_attribute(result, name, value)
        snapshot = result_snapshot_type(
            value=result,
            verifier=exact_verifier,
            envelope_encoded=envelope.encoded,
            authority_manifest_sha256=exact_authenticated.authority_manifest_sha256,
            signer_role=exact_authenticated.signer_role,
            root_sha256=exact_root.sha256,
            request_intent_sha256=exact_intent.sha256,
            terminal_record_sha256=exact_record.sha256,
            artifact_directory_path=artifact_directory_path,
            verifier_capability=exact_verifier._sealed_result_capability,
        )
        with lock:
            if exact_id(result) in result_snapshots:
                raise authentication_error_type("retained-wire result identity was already issued")
            result_snapshots[exact_id(result)] = snapshot
        return require_result(exact_verifier, result)

    def require_result(
        verifier: object,
        result: object,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        exact_verifier = require_verifier(verifier)
        key = exact_id(result)
        with lock:
            snapshot = result_snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not result
            or snapshot.verifier is not exact_verifier
            or exact_type(result) is not result_type
        ):
            raise authentication_error_type(
                "retained-wire verifier result is not its exact sealed value"
            )
        try:
            canonical = decode_envelope(snapshot.envelope_encoded)
            fields = (
                result.authority_manifest_sha256,
                result.signer_role,
                result.root_sha256,
                result.request_intent_sha256,
                result.terminal_record_sha256,
                result.artifact_directory_path,
            )
            result_envelope = result.envelope
            result_capability = result._verifier_capability
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "retained-wire verifier result changed under validation"
            ) from error
        if (
            exact_type(result_envelope) is not envelope_type
            or canonical.encoded != snapshot.envelope_encoded
            or result_envelope != canonical
            or result_envelope.encoded != snapshot.envelope_encoded
            or fields
            != (
                snapshot.authority_manifest_sha256,
                snapshot.signer_role,
                snapshot.root_sha256,
                snapshot.request_intent_sha256,
                snapshot.terminal_record_sha256,
                snapshot.artifact_directory_path,
            )
            or result_capability is not snapshot.verifier_capability
        ):
            raise authentication_error_type(
                "retained-wire verifier result changed under validation"
            )
        return result

    def reauthenticate(
        verifier: object,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        exact_verifier = require_verifier(verifier)
        try:
            exact_record = decode_progress(terminal_record.encoded)
            exact_root = decode_root(root.encoded)
            exact_intent = decode_progress(request_intent.encoded)
        except (attribute_error_type, rejected_type) as error:
            raise authentication_error_type(
                "retained-wire repository values are not canonical"
            ) from error
        if (
            exact_record != terminal_record
            or exact_root != root
            or exact_intent != request_intent
            or exact_type(envelope) is not envelope_type
            or exact_type(artifact_directory_path) is not str_type
            or not artifact_directory_path.startswith("/")
            or not artifact_directory_path.endswith("/trusted-time")
            or artifact_directory_path == "/trusted-time"
            or "//" in artifact_directory_path
            or "/./" in artifact_directory_path
            or "/../" in artifact_directory_path
            or "\0" in artifact_directory_path
        ):
            raise authentication_error_type("retained-wire repository inputs are not exact")
        if envelope.frame_type not in {"clean_stop_result", "clean_stop_error"}:
            raise authentication_error_type("retained-wire verifier accepts only terminal frames")
        prefix = (
            "clean_stop_result"
            if envelope.frame_type == "clean_stop_result"
            else "clean_stop_error"
        )
        expected_stage = (
            result_retained_stage
            if envelope.frame_type == "clean_stop_result"
            else error_retained_stage
        )
        evidence = exact_record.evidence.to_dict()
        file_name = wire_file_name(envelope)
        if (
            exact_record.ordinal != 2
            or exact_record.stage is not expected_stage
            or exact_record.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.predecessor_sha256 != exact_intent.sha256
            or exact_record.effect_kind != prefix
            or exact_record.deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or evidence.get("intent_sha256") != exact_intent.sha256
            or evidence.get(f"{prefix}_sha256") != envelope.sha256
            or evidence.get(f"{prefix}_artifact_name") != file_name
            or evidence.get(f"{prefix}_artifact_path") != f"{artifact_directory_path}/{file_name}"
        ):
            raise authentication_error_type(
                "retained-wire terminal record crossed its root, intent, or artifact"
            )
        authenticated = authenticate_retained_wire(
            envelope.encoded,
            authority_manifest=exact_verifier._authority_manifest,
            root=exact_root,
            request_intent=exact_intent,
        )
        try:
            basis = request_basis_from_root(exact_root)
            request = request_from_prefix(exact_root, basis, exact_intent)
            proof = bind_terminal_proof(authenticated)
            wire_evidence = capture_wire_evidence(
                evidence,
                proof=proof,
                request=request,
                root=exact_root,
                responder_identity_sha256=exact_root.supervisor_process_epoch_sha256,
            )
        except rejected_type as error:
            raise authentication_error_type(
                "retained terminal payload or evidence is not exact"
            ) from error
        if wire_evidence.to_dict() != evidence:
            raise authentication_error_type(
                "retained-wire evidence changed under terminal validation"
            )
        return seal_result(
            exact_verifier,
            authenticated=authenticated,
            root=exact_root,
            request_intent=exact_intent,
            terminal_record=exact_record,
            artifact_directory_path=artifact_directory_path,
        )

    return build, require_verifier, reauthenticate, seal_result, require_result


(
    _build_injected_lifecycle_v2_ed25519_retained_wire_verifier,
    _require_exact_retained_wire_verifier,
    _reauthenticate_exact_retained_terminal_wire,
    _seal_exact_retained_wire_result,
    _require_exact_retained_wire_result,
) = _build_retained_wire_verifier_endpoints()


def _install_retained_wire_verifier_methods(
    *,
    require_verifier: Callable[[object], _LifecycleV2Ed25519RetainedWireVerifier],
    reauthenticate: Callable[..., _LifecycleV2Ed25519RetainedWireResult],
    require_result: Callable[..., _LifecycleV2Ed25519RetainedWireResult],
) -> None:
    def require_owner(self: _LifecycleV2Ed25519RetainedWireVerifier) -> None:
        require_verifier(self)

    def reauthenticate_method(
        self: _LifecycleV2Ed25519RetainedWireVerifier,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        return reauthenticate(
            self,
            envelope=envelope,
            root=root,
            request_intent=request_intent,
            terminal_record=terminal_record,
            artifact_directory_path=artifact_directory_path,
        )

    def require_result_method(
        self: _LifecycleV2Ed25519RetainedWireVerifier,
        result: object,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        return require_result(self, result)

    type.__setattr__(_LifecycleV2Ed25519RetainedWireVerifier, "_require_owner", require_owner)
    type.__setattr__(
        _LifecycleV2Ed25519RetainedWireVerifier,
        "reauthenticate_retained_terminal_wire",
        reauthenticate_method,
    )
    type.__setattr__(
        _LifecycleV2Ed25519RetainedWireVerifier,
        "require_exact_authenticated_retained_terminal_wire",
        require_result_method,
    )


_install_retained_wire_verifier_methods(
    require_verifier=_require_exact_retained_wire_verifier,
    reauthenticate=_reauthenticate_exact_retained_terminal_wire,
    require_result=_require_exact_retained_wire_result,
)


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
    "consume_authenticated_lifecycle_v2_recovery_classification_envelope",
    "lifecycle_v2_ed25519_non_authority_facts",
]
