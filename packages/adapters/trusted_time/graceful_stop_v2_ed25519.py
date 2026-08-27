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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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

    snapshots: dict[int, _AuthenticatedManifestIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthorityManifest:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not AuthenticatedLifecycleV2TransportAuthorityManifest
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport authority manifest is not authenticated"
            )
        try:
            canonical = decode_lifecycle_v2_transport_authority_manifest(snapshot.manifest_encoded)
            value_manifest = value.manifest
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "authenticated transport authority manifest changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or type(value_manifest) is not LifecycleV2TransportAuthorityManifest
            or canonical.encoded != snapshot.manifest_encoded
            or value_manifest != canonical
            or value_manifest.encoded != snapshot.manifest_encoded
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise LifecycleV2TransportAuthenticationError(
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
        result = object.__new__(AuthenticatedLifecycleV2TransportAuthorityManifest)
        root_digest = hashlib.sha256(public_key).hexdigest()
        object.__setattr__(result, "manifest", manifest)
        object.__setattr__(result, "root_public_key_sha256", root_digest)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _AuthenticatedManifestIssuanceSnapshot(
            value=result,
            manifest_encoded=manifest.encoded,
            root_public_key_sha256=root_digest,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "transport authority manifest identity was already authenticated"
                )
            snapshots[id(result)] = snapshot
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

    snapshots: dict[int, _AuthenticatedSelectionIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthoritySelection:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not AuthenticatedLifecycleV2TransportAuthoritySelection
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport authority selection is not authenticated"
            )
        try:
            canonical = decode_lifecycle_v2_transport_authority_selection(
                snapshot.selection_encoded
            )
            value_selection = value.selection
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "authenticated transport authority selection changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or type(value_selection) is not LifecycleV2TransportAuthoritySelection
            or canonical.encoded != snapshot.selection_encoded
            or value_selection != canonical
            or value_selection.encoded != snapshot.selection_encoded
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise LifecycleV2TransportAuthenticationError(
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
            selection = decode_lifecycle_v2_transport_authority_selection(encoded)
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2TransportAuthenticationError(
                "transport authority selection is not canonical"
            ) from error
        public_key = reviewed_root_public_key if type(reviewed_root_public_key) is bytes else b""
        _verify(public_key, selection.signature_input, selection.signature)
        result = object.__new__(AuthenticatedLifecycleV2TransportAuthoritySelection)
        root_digest = hashlib.sha256(public_key).hexdigest()
        object.__setattr__(result, "selection", selection)
        object.__setattr__(result, "root_public_key_sha256", root_digest)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _AuthenticatedSelectionIssuanceSnapshot(
            value=result,
            selection_encoded=selection.encoded,
            root_public_key_sha256=root_digest,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "transport authority selection identity was already authenticated"
                )
            snapshots[id(result)] = snapshot
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
]:
    """Keep resolved-chain issuance behind complete signature verification."""

    snapshots: dict[int, _AuthenticatedAuthorityIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportAuthority:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not AuthenticatedLifecycleV2TransportAuthority
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport authority resolution is not authenticated"
            )
        try:
            manifests = tuple(
                _require_authenticated_manifest(item) for item in snapshot.authenticated_manifests
            )
            selections = tuple(
                _require_authenticated_selection(item) for item in snapshot.authenticated_selections
            )
            canonical_manifests = tuple(
                decode_lifecycle_v2_transport_authority_manifest(encoded)
                for encoded in snapshot.manifest_encoded_chain
            )
            canonical_selections = tuple(
                decode_lifecycle_v2_transport_authority_selection(encoded)
                for encoded in snapshot.selection_encoded_chain
            )
            resolution = resolve_lifecycle_v2_transport_authority(
                canonical_manifests,
                canonical_selections,
            )
            value_resolution = value.resolution
            value_manifests = value.authenticated_manifests
            value_selections = value.authenticated_selections
            value_root_digest = value.root_public_key_sha256
            value_capability = value._capability
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "authenticated transport authority changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_manifests is not snapshot.authenticated_manifests
            or value_selections is not snapshot.authenticated_selections
            or manifests != snapshot.authenticated_manifests
            or selections != snapshot.authenticated_selections
            or tuple(item.manifest for item in manifests) != canonical_manifests
            or tuple(item.selection for item in selections) != canonical_selections
            or value_resolution != resolution
            or value_root_digest != snapshot.root_public_key_sha256
        ):
            raise LifecycleV2TransportAuthenticationError(
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
            raise LifecycleV2TransportAuthenticationError(
                "transport authority chains cannot be empty"
            )
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
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _AuthenticatedAuthorityIssuanceSnapshot(
            value=result,
            manifest_encoded_chain=tuple(item.manifest.encoded for item in manifests),
            selection_encoded_chain=tuple(item.selection.encoded for item in selections),
            authenticated_manifests=manifests,
            authenticated_selections=selections,
            root_public_key_sha256=root_digest,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "transport authority identity was already authenticated"
                )
            snapshots[id(result)] = snapshot
        return require(result)

    return authenticate, require


(
    authenticate_lifecycle_v2_transport_authority,
    _require_authenticated_authority,
) = _build_authority_authentication_endpoints()


def authenticated_lifecycle_v2_recovery_manifest_for_root(
    authority: AuthenticatedLifecycleV2TransportAuthority,
    *,
    root_manifest_sha256: object,
    root_generation: object,
) -> AuthenticatedLifecycleV2TransportAuthorityManifest | None:
    """Return the authenticated recovery key only for an exact pinned root."""

    authenticated_authority = _require_authenticated_authority(authority)
    try:
        recovery = lifecycle_v2_recovery_manifest_for_root(
            authenticated_authority.resolution,
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
        for item in authenticated_authority.authenticated_manifests
        if item.manifest.sha256 == recovery.sha256
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


def _authenticated_recovery_classification_issuance_registry() -> tuple[
    Callable[..., AuthenticatedLifecycleV2RecoveryClassificationEnvelope],
    Callable[[object], AuthenticatedLifecycleV2RecoveryClassificationEnvelope],
    Callable[[object], tuple[LifecycleV2RecoveryClassificationEnvelope, str, str, str]],
]:
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
        key = id(value)
        snapshot = _AuthenticatedRecoveryClassificationIssuanceSnapshot(
            value=value,
            envelope_encoded=envelope_encoded,
            root_sha256=root_sha256,
            classified_transcript_sha256=classified_transcript_sha256,
            authority_manifest_sha256=authority_manifest_sha256,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
            capability=issuance_capability,
        )
        with lock:
            if key in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "recovery classification identity was already authenticated"
                )
            snapshots[key] = snapshot

    def lookup(
        value: object,
        *,
        consume: bool,
    ) -> _AuthenticatedRecoveryClassificationIssuanceSnapshot:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
            if snapshot is None or snapshot.value is not value:
                raise LifecycleV2TransportAuthenticationError(
                    "recovery classification has no exact authenticated issuance"
                )
            if consume:
                if (
                    os.getpid() != snapshot.origin_pid
                    or threading.current_thread() is not snapshot.origin_thread
                ):
                    raise LifecycleV2TransportAuthenticationError(
                        "authenticated recovery classification owner is invalid"
                    )
                if key in consumed:
                    raise LifecycleV2TransportAuthenticationError(
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
        envelope, exact_root, exact_transcript, manifest = (
            _verify_lifecycle_v2_recovery_classification_envelope(
                encoded,
                authority=authority,
                root=root,
                classified_transcript=classified_transcript,
            )
        )
        result = object.__new__(AuthenticatedLifecycleV2RecoveryClassificationEnvelope)
        object.__setattr__(result, "envelope", envelope)
        object.__setattr__(result, "root_sha256", exact_root.sha256)
        object.__setattr__(result, "classified_transcript_sha256", exact_transcript.sha256)
        object.__setattr__(result, "authority_manifest_sha256", manifest.sha256)
        object.__setattr__(result, "_origin_pid", os.getpid())
        object.__setattr__(result, "_origin_thread", threading.current_thread())
        object.__setattr__(result, "_consumed", False)
        object.__setattr__(result, "_capability", issuance_capability)
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
        return _require_authenticated_recovery_classification_issuance(value, snapshot)

    def consume_value(
        value: object,
    ) -> tuple[LifecycleV2RecoveryClassificationEnvelope, str, str, str]:
        snapshot = lookup(value, consume=True)
        authenticated = _require_authenticated_recovery_classification_issuance(value, snapshot)
        object.__setattr__(authenticated, "_consumed", True)
        return (
            decode_lifecycle_v2_recovery_classification_envelope(snapshot.envelope_encoded),
            snapshot.root_sha256,
            snapshot.classified_transcript_sha256,
            snapshot.authority_manifest_sha256,
        )

    return authenticate, require, consume_value


(
    authenticate_lifecycle_v2_recovery_classification_envelope,
    _require_authenticated_lifecycle_v2_recovery_classification_envelope,
    _consume_authenticated_lifecycle_v2_recovery_envelope_value,
) = _authenticated_recovery_classification_issuance_registry()

_install_authenticated_lifecycle_v2_recovery_adapter_endpoint(
    _consume_authenticated_lifecycle_v2_recovery_envelope_value
)


def _require_authenticated_recovery_classification_issuance(
    value: object,
    snapshot: _AuthenticatedRecoveryClassificationIssuanceSnapshot,
) -> AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
    if type(value) is not AuthenticatedLifecycleV2RecoveryClassificationEnvelope:
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification is not authenticated"
        )
    try:
        canonical = decode_lifecycle_v2_recovery_classification_envelope(snapshot.envelope_encoded)
        value_envelope = value.envelope
        value_root_sha256 = value.root_sha256
        value_transcript_sha256 = value.classified_transcript_sha256
        value_manifest_sha256 = value.authority_manifest_sha256
        value_origin_pid = value._origin_pid
        value_origin_thread = value._origin_thread
        value_consumed = value._consumed
        value_capability = value._capability
    except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise LifecycleV2TransportAuthenticationError(
            "authenticated recovery classification changed under validation"
        ) from error
    if (
        snapshot.value is not value
        or value_capability is not snapshot.capability
        or os.getpid() != snapshot.origin_pid
        or threading.current_thread() is not snapshot.origin_thread
        or value_origin_pid != snapshot.origin_pid
        or value_origin_thread is not snapshot.origin_thread
        or value_consumed is not False
        or canonical.encoded != snapshot.envelope_encoded
        or canonical.root_sha256 != snapshot.root_sha256
        or canonical.transcript_sha256 != snapshot.classified_transcript_sha256
        or canonical.transport_authority_manifest_sha256 != snapshot.authority_manifest_sha256
        or type(value_envelope) is not LifecycleV2RecoveryClassificationEnvelope
        or value_envelope != canonical
        or value_envelope.encoded != snapshot.envelope_encoded
        or value_root_sha256 != snapshot.root_sha256
        or value_transcript_sha256 != snapshot.classified_transcript_sha256
        or value_manifest_sha256 != snapshot.authority_manifest_sha256
    ):
        raise LifecycleV2TransportAuthenticationError(
            "authenticated recovery classification changed under validation"
        )
    return value


def _verify_lifecycle_v2_recovery_classification_envelope(
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
    for entry in exact_transcript.entries:
        expected_stage = NORMAL_STAGE_BY_ORDINAL.get(entry.ordinal)
        if entry.ordinal == 2 and entry.stage is LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED:
            if entry is not exact_transcript.entries[-1]:
                raise LifecycleV2TransportAuthenticationError(
                    "recovery classification crossed an impossible lifecycle prefix"
                )
            continue
        if expected_stage is None or entry.stage is not expected_stage:
            raise LifecycleV2TransportAuthenticationError(
                "recovery classification crossed an impossible lifecycle prefix"
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
        raise LifecycleV2TransportAuthenticationError(
            "recovery classification crossed its root, prefix, or recovery generation"
        )
    _verify(manifest.recovery_public_key, envelope.signature_input, envelope.signature)
    return envelope, exact_root, exact_transcript, manifest


def consume_authenticated_lifecycle_v2_recovery_classification_envelope(
    authenticated_envelope: object,
    *,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
    recorded_at_utc: str,
) -> LifecycleV2AuthenticatedRecoveryIntent:
    """Consume one authenticated classifier into its exact durable intent."""

    return _consume_authenticated_lifecycle_v2_recovery_classification_envelope(
        authenticated_envelope,
        root=root,
        classified_transcript=classified_transcript,
        recorded_at_utc=recorded_at_utc,
    )


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


def _verify_lifecycle_v2_handshake(
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    *,
    host_hello_encoded: bytes,
    supervisor_hello_encoded: bytes,
    host_confirmation_encoded: bytes,
) -> tuple[LifecycleV2Handshake, str]:
    """Verify and correlate the exact three-message mutual handshake."""

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
    return handshake, manifest.sha256


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
    snapshots: dict[int, _AuthenticatedHandshakeIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2Handshake:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not AuthenticatedLifecycleV2Handshake
        ):
            raise LifecycleV2TransportAuthenticationError(
                "lifecycle-v2 handshake is not authenticated"
            )
        try:
            canonical_handshake = bind_lifecycle_v2_handshake(
                decode_lifecycle_v2_host_hello(snapshot.host_hello_encoded),
                decode_lifecycle_v2_supervisor_hello(snapshot.supervisor_hello_encoded),
                decode_lifecycle_v2_host_channel_confirmation(snapshot.host_confirmation_encoded),
            )
            value_handshake = value.handshake
            value_manifest_sha256 = value.authority_manifest_sha256
            value_capability = value._capability
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "authenticated lifecycle-v2 handshake changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_handshake != canonical_handshake
            or value_manifest_sha256 != snapshot.authority_manifest_sha256
        ):
            raise LifecycleV2TransportAuthenticationError(
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

        authenticated_authority = _require_authenticated_authority(authority)
        selected = authenticated_authority.selected_manifest
        if selected is None:
            raise LifecycleV2TransportAuthenticationError(
                "current transport authority selection denies new roots"
            )
        handshake, manifest_sha256 = _verify_lifecycle_v2_handshake(
            selected,
            host_hello_encoded=host_hello_encoded,
            supervisor_hello_encoded=supervisor_hello_encoded,
            host_confirmation_encoded=host_confirmation_encoded,
        )
        result = object.__new__(AuthenticatedLifecycleV2Handshake)
        object.__setattr__(result, "handshake", handshake)
        object.__setattr__(result, "authority_manifest_sha256", manifest_sha256)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _AuthenticatedHandshakeIssuanceSnapshot(
            value=result,
            host_hello_encoded=handshake.host_hello.encoded,
            supervisor_hello_encoded=handshake.supervisor_hello.encoded,
            host_confirmation_encoded=handshake.host_confirmation.encoded,
            authority_manifest_sha256=manifest_sha256,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "lifecycle-v2 handshake identity was already authenticated"
                )
            snapshots[id(result)] = snapshot
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
        return _derive_lifecycle_v2_transport_frame_expectation(
            root,
            request_intent,
            frame_type=frame_type,
        )


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
    snapshots: dict[int, _TransportFrameExpectationIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> _LifecycleV2TransportFrameExpectation:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not _LifecycleV2TransportFrameExpectation
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport frame expectation has no exact issuance"
            )
        try:
            fields = tuple(getattr(value, name) for name in _EXPECTATION_FIELD_NAMES)
            capability = value._capability
        except AttributeError as error:
            raise LifecycleV2TransportAuthenticationError(
                "transport frame expectation changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or capability is not issuance_capability
            or fields != snapshot.fields
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport frame expectation changed under validation"
            )
        return value

    def derive(
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
            exact_root != root
            or exact_intent != request_intent
            or exact_intent.ordinal != 1
            or exact_intent.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
            or exact_intent.root_sha256 != exact_root.sha256
            or exact_intent.predecessor_sha256 != exact_root.sha256
            or frame_type not in {"clean_stop_request", "clean_stop_result", "clean_stop_error"}
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire expectation does not bind the ordinal-one prefix"
            )
        host_frame = frame_type == "clean_stop_request"
        result = object.__new__(_LifecycleV2TransportFrameExpectation)
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
            lifecycle_v2_dispatch_prefix_sha256(exact_root, exact_intent),
            2 if host_frame else 1,
            exact_root.clean_stop_result_deadline_boottime_ns,
        )
        for name, value in zip(_EXPECTATION_FIELD_NAMES, fields, strict=True):
            object.__setattr__(result, name, value)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _TransportFrameExpectationIssuanceSnapshot(
            value=result,
            fields=fields,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "transport frame expectation identity was already issued"
                )
            snapshots[id(result)] = snapshot
        return require(result)

    return derive, require


(
    _derive_lifecycle_v2_transport_frame_expectation,
    _require_lifecycle_v2_transport_frame_expectation,
) = _build_transport_frame_expectation_endpoints()


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


def _verify_lifecycle_v2_transport_frame(
    encoded: object,
    *,
    authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    expectation: _LifecycleV2TransportFrameExpectation,
) -> tuple[UnverifiedLifecycleV2TransportEnvelope, str, str]:
    """Verify one request, result, or error against exact correlators."""

    authenticated = _require_authenticated_manifest(authority_manifest)
    exact_expectation = _require_lifecycle_v2_transport_frame_expectation(expectation)
    try:
        envelope = decode_unverified_lifecycle_v2_transport_envelope(encoded)
    except TrustedTimeGracefulStopV2Rejected as error:
        raise LifecycleV2TransportAuthenticationError(
            "transport envelope is not structurally canonical"
        ) from error
    _validate_transport_envelope_formula(envelope)
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
    if any(fields[name] != expected for name, expected in expected_fields.items()):
        raise LifecycleV2TransportAuthenticationError(
            "transport envelope crossed an expected retained-wire correlator"
        )
    manifest = authenticated.manifest
    if (
        manifest.sha256 != exact_expectation.transport_authority_manifest_sha256
        or manifest.environment != exact_expectation.environment
        or manifest.generation != exact_expectation.key_generation
    ):
        raise LifecycleV2TransportAuthenticationError(
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
        raise LifecycleV2TransportAuthenticationError(
            "transport frame crossed its authenticated signer role"
        )
    _verify(public_key, _transport_envelope_signature_input(envelope), envelope.signature)
    return envelope, manifest.sha256, signer_role


def _build_transport_frame_authentication_endpoints() -> tuple[
    Callable[..., AuthenticatedLifecycleV2TransportEnvelope],
    Callable[[object], AuthenticatedLifecycleV2TransportEnvelope],
]:
    snapshots: dict[int, _AuthenticatedTransportEnvelopeIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require(value: object) -> AuthenticatedLifecycleV2TransportEnvelope:
        key = id(value)
        with lock:
            snapshot = snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not AuthenticatedLifecycleV2TransportEnvelope
        ):
            raise LifecycleV2TransportAuthenticationError(
                "transport envelope has no exact authenticated issuance"
            )
        try:
            canonical = decode_unverified_lifecycle_v2_transport_envelope(snapshot.envelope_encoded)
            value_envelope = value.envelope
            value_manifest_sha256 = value.authority_manifest_sha256
            value_signer_role = value.signer_role
            value_capability = value._capability
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "authenticated transport envelope changed under validation"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or type(value_envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or canonical.encoded != snapshot.envelope_encoded
            or value_envelope != canonical
            or value_envelope.encoded != snapshot.envelope_encoded
            or value_manifest_sha256 != snapshot.authority_manifest_sha256
            or value_signer_role != snapshot.signer_role
        ):
            raise LifecycleV2TransportAuthenticationError(
                "authenticated transport envelope changed under validation"
            )
        return value

    def authenticate(
        encoded: object,
        *,
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
        expectation: _LifecycleV2TransportFrameExpectation,
    ) -> AuthenticatedLifecycleV2TransportEnvelope:
        envelope, manifest_sha256, signer_role = _verify_lifecycle_v2_transport_frame(
            encoded,
            authority_manifest=authority_manifest,
            expectation=expectation,
        )
        result = object.__new__(AuthenticatedLifecycleV2TransportEnvelope)
        object.__setattr__(result, "envelope", envelope)
        object.__setattr__(result, "authority_manifest_sha256", manifest_sha256)
        object.__setattr__(result, "signer_role", signer_role)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _AuthenticatedTransportEnvelopeIssuanceSnapshot(
            value=result,
            envelope_encoded=envelope.encoded,
            authority_manifest_sha256=manifest_sha256,
            signer_role=signer_role,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "transport envelope identity was already authenticated"
                )
            snapshots[id(result)] = snapshot
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


def bind_authenticated_lifecycle_v2_terminal_envelope_proof(
    authenticated_envelope: object,
) -> LifecycleV2AuthenticatedTerminalEnvelopeProof:
    """Cross the reviewed adapter-to-domain seam for one authenticated terminal frame."""

    return _mint_authenticated_lifecycle_v2_terminal_envelope_proof(
        authenticated_envelope,
    )


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
        _require_exact_retained_wire_verifier(self)

    def reauthenticate_retained_terminal_wire(
        self,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
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
        return _seal_exact_retained_wire_result(
            self,
            authenticated=authenticated,
            root=exact_root,
            request_intent=exact_intent,
            terminal_record=exact_record,
            artifact_directory_path=artifact_directory_path,
        )

    def require_exact_authenticated_retained_terminal_wire(
        self,
        result: object,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        return _require_exact_retained_wire_result(self, result)


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
]:
    verifier_snapshots: dict[int, _RetainedWireVerifierIssuanceSnapshot] = {}
    result_snapshots: dict[int, _RetainedWireResultIssuanceSnapshot] = {}
    issuance_capability = object()
    lock = threading.Lock()

    def require_verifier(value: object) -> _LifecycleV2Ed25519RetainedWireVerifier:
        key = id(value)
        with lock:
            snapshot = verifier_snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not value
            or type(value) is not _LifecycleV2Ed25519RetainedWireVerifier
        ):
            raise LifecycleV2TransportAuthenticationError("retained-wire verifier owner is invalid")
        try:
            authenticated_manifest = _require_authenticated_manifest(snapshot.authority_manifest)
            value_manifest = value._authority_manifest
            value_pid = value._origin_pid
            value_thread = value._origin_thread
            value_result_capability = value._sealed_result_capability
            value_capability = value._capability
        except AttributeError as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier owner is invalid"
            ) from error
        if (
            os.getpid() != snapshot.origin_pid
            or threading.current_thread() is not snapshot.origin_thread
            or value_pid != snapshot.origin_pid
            or value_thread is not snapshot.origin_thread
            or value_capability is not issuance_capability
            or value_manifest is not snapshot.authority_manifest
            or authenticated_manifest.manifest.encoded != snapshot.authority_manifest_encoded
            or value_result_capability is not snapshot.sealed_result_capability
        ):
            raise LifecycleV2TransportAuthenticationError("retained-wire verifier owner is invalid")
        return value

    def build(
        authority_manifest: AuthenticatedLifecycleV2TransportAuthorityManifest,
    ) -> _LifecycleV2Ed25519RetainedWireVerifier:
        authenticated = _require_authenticated_manifest(authority_manifest)
        result = object.__new__(_LifecycleV2Ed25519RetainedWireVerifier)
        result_capability = object()
        object.__setattr__(result, "_authority_manifest", authenticated)
        object.__setattr__(result, "_origin_pid", os.getpid())
        object.__setattr__(result, "_origin_thread", threading.current_thread())
        object.__setattr__(result, "_sealed_result_capability", result_capability)
        object.__setattr__(result, "_capability", issuance_capability)
        snapshot = _RetainedWireVerifierIssuanceSnapshot(
            value=result,
            authority_manifest=authenticated,
            authority_manifest_encoded=authenticated.manifest.encoded,
            sealed_result_capability=result_capability,
            origin_pid=os.getpid(),
            origin_thread=threading.current_thread(),
        )
        with lock:
            if id(result) in verifier_snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "retained-wire verifier identity was already issued"
                )
            verifier_snapshots[id(result)] = snapshot
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
        exact_authenticated = _require_authenticated_lifecycle_v2_transport_envelope(authenticated)
        try:
            exact_root = decode_lifecycle_v2_root(root.encoded)
            exact_intent = decode_lifecycle_v2_progress_record(request_intent.encoded)
            exact_record = decode_lifecycle_v2_progress_record(terminal_record.encoded)
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire result inputs are not canonical"
            ) from error
        envelope = exact_authenticated.envelope
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
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire result crossed its verifier, root, intent, or artifact"
            )
        try:
            request = LifecycleV2CleanStopRequest.from_prefix(
                exact_root,
                LifecycleV2CleanStopRequestBasis.from_root(exact_root),
                exact_intent,
            )
            proof = bind_authenticated_lifecycle_v2_terminal_envelope_proof(exact_authenticated)
            wire_evidence = LifecycleV2TerminalWireEvidence.capture(
                evidence,
                proof=proof,
                request=request,
                root=exact_root,
                responder_identity_sha256=exact_root.supervisor_process_epoch_sha256,
            )
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire result terminal evidence is not exact"
            ) from error
        if wire_evidence.to_dict() != evidence:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire result terminal evidence changed"
            )
        result = object.__new__(_LifecycleV2Ed25519RetainedWireResult)
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
            object.__setattr__(result, name, value)
        snapshot = _RetainedWireResultIssuanceSnapshot(
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
            if id(result) in result_snapshots:
                raise LifecycleV2TransportAuthenticationError(
                    "retained-wire result identity was already issued"
                )
            result_snapshots[id(result)] = snapshot
        return require_result(exact_verifier, result)

    def require_result(
        verifier: object,
        result: object,
    ) -> _LifecycleV2Ed25519RetainedWireResult:
        exact_verifier = require_verifier(verifier)
        key = id(result)
        with lock:
            snapshot = result_snapshots.get(key)
        if (
            snapshot is None
            or snapshot.value is not result
            or snapshot.verifier is not exact_verifier
            or type(result) is not _LifecycleV2Ed25519RetainedWireResult
        ):
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result is not its exact sealed value"
            )
        try:
            canonical = decode_unverified_lifecycle_v2_transport_envelope(snapshot.envelope_encoded)
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
        except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result changed under validation"
            ) from error
        if (
            type(result_envelope) is not UnverifiedLifecycleV2TransportEnvelope
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
            raise LifecycleV2TransportAuthenticationError(
                "retained-wire verifier result changed under validation"
            )
        return result

    return build, require_verifier, seal_result, require_result


(
    _build_injected_lifecycle_v2_ed25519_retained_wire_verifier,
    _require_exact_retained_wire_verifier,
    _seal_exact_retained_wire_result,
    _require_exact_retained_wire_result,
) = _build_retained_wire_verifier_endpoints()


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
