"""Canonical lifecycle-v2 transport identity contracts for ADR 0121.

The values in this module are effect-free.  They do not read ``/proc``, open a
socket, load a key, select an installed authority, or grant graceful-stop
authority.  Native owners may eventually capture the primitive facts and pass
them through these closed codecs; milestone-one tests use injected values.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Self

from packages.domain.trusted_time_graceful_stop_v2 import (
    FrozenJsonObject,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
)

TRANSPORT_AUTHORITY_MANIFEST_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-transport-authority-v1"
)
TRANSPORT_AUTHORITY_SELECTION_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-transport-authority-selection-v1"
)
PROCESS_EPOCH_CONTRACT_VERSION = "phase6d-trusted-time-graceful-stop-process-epoch-v2"
HOST_HELLO_CONTRACT_VERSION = "phase6d-trusted-time-graceful-stop-host-hello-v2"
SUPERVISOR_HELLO_CONTRACT_VERSION = "phase6d-trusted-time-graceful-stop-supervisor-hello-v2"
HOST_CHANNEL_CONFIRMATION_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-host-channel-confirmation-v2"
)
CHANNEL_BINDING_CONTRACT_VERSION = "phase6d-trusted-time-graceful-stop-channel-v2"
TRANSPORT_SERVICE = "trusted-time-graceful-stop-transport-v2"
TRANSPORT_PROTOCOL_VERSION = 2
SUPERVISOR_SOCKET_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/transport/supervisor.sock"

TRANSPORT_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/transport-authority/v1"
)
TRANSPORT_AUTHORITY_SELECTION_SIGNATURE_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/transport-authority-selection/v1"
)
BOOT_EPOCH_DIGEST_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/boot/v2"
PROCESS_EPOCH_DIGEST_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/process-epoch/v2"
PEER_CREDENTIAL_DIGEST_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/peer-credential/v2"
HOST_SOCKET_IDENTITY_DIGEST_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/host-socket-identity/v2"
)
SUPERVISOR_SOCKET_IDENTITY_DIGEST_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/supervisor-socket-identity/v2"
)
HOST_HELLO_SIGNATURE_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/host-hello/v2"
SUPERVISOR_HELLO_SIGNATURE_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/supervisor-hello/v2"
HOST_CHANNEL_CONFIRMATION_SIGNATURE_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/host-channel-confirmation/v2"
)
CHANNEL_DIGEST_DOMAIN = "AutoQuantTrader/trusted-time/graceful-stop/channel/v2"

AUTHORITY_MAXIMUM_BYTES = 64 * 1_024
PROCESS_EPOCH_MAXIMUM_BYTES = 16 * 1_024
IDENTITY_MAXIMUM_BYTES = 16 * 1_024
HOST_HELLO_MAXIMUM_BYTES = 8_192
SUPERVISOR_HELLO_MAXIMUM_BYTES = 12_288
HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES = 8_192
MAXIMUM_SIGNED_INTEGER = 2**63 - 1
MAXIMUM_UID_GID = 2**32 - 2

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _require_fields(value: dict[str, object], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        raise TrustedTimeGracefulStopV2Rejected("transport identity field set is not exact")


def _require_identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(
            f"{name} must be a bounded canonical ASCII identifier"
        )
    return value


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} must be lowercase SHA-256")
    return value


def _require_optional_sha256(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, name)


def _require_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAXIMUM_SIGNED_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is outside its integer bounds")
    return value


def _require_canonical_base64(
    value: object,
    name: str,
    *,
    exact_length: int,
) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical base64") from error
    if len(decoded) != exact_length or base64.b64encode(decoded).decode("ascii") != value:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical base64")
    return decoded


def _require_absolute_path(value: object, name: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value == "/"
        or "//" in value
        or "/./" in value
        or "/../" in value
        or value.endswith("/")
        or len(value.encode("utf-8")) > 255
    ):
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not an exact absolute path")
    return value


def _require_sorted_options(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise TrustedTimeGracefulStopV2Rejected("mount_options must be nonempty text values")
    options = tuple(value)
    if tuple(sorted(options)) != options or len(set(options)) != len(options):
        raise TrustedTimeGracefulStopV2Rejected("mount_options must be sorted and duplicate-free")
    return options


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_bytes(domain: str, encoded: bytes) -> bytes:
    return domain.encode("ascii") + b"\0" + encoded


def _domain_sha256(domain: str, encoded: bytes) -> str:
    return _sha256(_domain_bytes(domain, encoded))


def _unsigned_fields(fields: FrozenJsonObject) -> dict[str, object]:
    value = fields.to_dict()
    value.pop("signature_ed25519_base64")
    return value


_MANIFEST_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TransportAuthorityManifest:
    """One structurally exact, root-signed transport-key generation."""

    fields: FrozenJsonObject
    signature: bytes
    host_public_key: bytes
    supervisor_public_key: bytes
    recovery_public_key: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport authority manifests require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _MANIFEST_FIELDS)
        if (
            fields["contract_version"] != TRANSPORT_AUTHORITY_MANIFEST_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "transport_authority_manifest_issued"
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority manifest discriminator is invalid"
            )
        _require_identifier(fields["environment"], "environment")
        generation = _require_int(fields["generation"], "generation", minimum=1)
        _require_identifier(fields["root_key_id"], "root_key_id")
        predecessor = _require_optional_sha256(
            fields["predecessor_manifest_sha256"], "predecessor_manifest_sha256"
        )
        if (generation == 1) != (predecessor is None):
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority predecessor conflicts with generation"
            )
        key_ids = tuple(
            _require_identifier(fields[name], name)
            for name in ("host_key_id", "supervisor_key_id", "recovery_key_id")
        )
        if len(set(key_ids)) != 3:
            raise TrustedTimeGracefulStopV2Rejected("transport key roles must be distinct")
        public_keys = tuple(
            _require_canonical_base64(fields[name], name, exact_length=32)
            for name in (
                "host_public_key_base64",
                "supervisor_public_key_base64",
                "recovery_public_key_base64",
            )
        )
        if len(set(public_keys)) != 3:
            raise TrustedTimeGracefulStopV2Rejected("transport public keys must be distinct")
        signature = _require_canonical_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "signature", signature)
        object.__setattr__(result, "host_public_key", public_keys[0])
        object.__setattr__(result, "supervisor_public_key", public_keys[1])
        object.__setattr__(result, "recovery_public_key", public_keys[2])
        if len(result.encoded) > AUTHORITY_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("transport authority manifest is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            _unsigned_fields(self.fields), maximum_bytes=AUTHORITY_MAXIMUM_BYTES
        )

    @property
    def signature_input(self) -> bytes:
        return _domain_bytes(TRANSPORT_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=AUTHORITY_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)

    @property
    def environment(self) -> str:
        return self.to_dict()["environment"]  # type: ignore[return-value]

    @property
    def generation(self) -> int:
        return self.to_dict()["generation"]  # type: ignore[return-value]

    @property
    def root_key_id(self) -> str:
        return self.to_dict()["root_key_id"]  # type: ignore[return-value]

    @property
    def predecessor_manifest_sha256(self) -> str | None:
        return self.to_dict()["predecessor_manifest_sha256"]  # type: ignore[return-value]

    @property
    def host_key_id(self) -> str:
        return self.to_dict()["host_key_id"]  # type: ignore[return-value]

    @property
    def supervisor_key_id(self) -> str:
        return self.to_dict()["supervisor_key_id"]  # type: ignore[return-value]

    @property
    def recovery_key_id(self) -> str:
        return self.to_dict()["recovery_key_id"]  # type: ignore[return-value]


def decode_lifecycle_v2_transport_authority_manifest(
    encoded: object,
) -> LifecycleV2TransportAuthorityManifest:
    return LifecycleV2TransportAuthorityManifest.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=AUTHORITY_MAXIMUM_BYTES)
    )


_SELECTION_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TransportAuthoritySelection:
    """One structurally exact, root-signed selection or denial record."""

    fields: FrozenJsonObject
    signature: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport authority selections require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _SELECTION_FIELDS)
        if (
            fields["contract_version"] != TRANSPORT_AUTHORITY_SELECTION_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "transport_authority_selection_recorded"
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority selection discriminator is invalid"
            )
        _require_identifier(fields["environment"], "environment")
        sequence = _require_int(fields["selection_sequence"], "selection_sequence", minimum=1)
        predecessor = _require_optional_sha256(
            fields["predecessor_selection_sha256"], "predecessor_selection_sha256"
        )
        if (sequence == 1) != (predecessor is None):
            raise TrustedTimeGracefulStopV2Rejected(
                "transport selection predecessor conflicts with sequence"
            )
        disposition = fields["disposition"]
        if disposition not in {"generation_selected", "new_roots_denied"}:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority selection disposition is invalid"
            )
        reason = fields["reason_code"]
        if reason not in {
            "initial",
            "rotation",
            "suspected_compromise",
            "administrative_hold",
        }:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority selection reason is invalid"
            )
        if sequence == 1 and reason != "initial":
            raise TrustedTimeGracefulStopV2Rejected(
                "first transport authority selection must be initial"
            )
        if sequence > 1 and reason == "initial":
            raise TrustedTimeGracefulStopV2Rejected(
                "later transport authority selection cannot be initial"
            )
        selected_digest = _require_optional_sha256(
            fields["selected_manifest_sha256"], "selected_manifest_sha256"
        )
        selected_generation = fields["selected_generation"]
        if disposition == "generation_selected":
            if selected_digest is None:
                raise TrustedTimeGracefulStopV2Rejected(
                    "selected generation requires a manifest digest"
                )
            _require_int(selected_generation, "selected_generation", minimum=1)
        elif selected_digest is not None or selected_generation is not None:
            raise TrustedTimeGracefulStopV2Rejected("new-roots denial cannot select a generation")
        _require_optional_sha256(fields["recovery_manifest_sha256"], "recovery_manifest_sha256")
        signature = _require_canonical_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "signature", signature)
        if len(result.encoded) > AUTHORITY_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("transport authority selection is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            _unsigned_fields(self.fields), maximum_bytes=AUTHORITY_MAXIMUM_BYTES
        )

    @property
    def signature_input(self) -> bytes:
        return _domain_bytes(TRANSPORT_AUTHORITY_SELECTION_SIGNATURE_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=AUTHORITY_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)

    @property
    def environment(self) -> str:
        return self.to_dict()["environment"]  # type: ignore[return-value]

    @property
    def sequence(self) -> int:
        return self.to_dict()["selection_sequence"]  # type: ignore[return-value]

    @property
    def disposition(self) -> str:
        return self.to_dict()["disposition"]  # type: ignore[return-value]

    @property
    def selected_manifest_sha256(self) -> str | None:
        return self.to_dict()["selected_manifest_sha256"]  # type: ignore[return-value]

    @property
    def selected_generation(self) -> int | None:
        return self.to_dict()["selected_generation"]  # type: ignore[return-value]

    @property
    def recovery_manifest_sha256(self) -> str | None:
        return self.to_dict()["recovery_manifest_sha256"]  # type: ignore[return-value]

    @property
    def predecessor_selection_sha256(self) -> str | None:
        return self.to_dict()["predecessor_selection_sha256"]  # type: ignore[return-value]


def decode_lifecycle_v2_transport_authority_selection(
    encoded: object,
) -> LifecycleV2TransportAuthoritySelection:
    return LifecycleV2TransportAuthoritySelection.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=AUTHORITY_MAXIMUM_BYTES)
    )


@dataclass(frozen=True, slots=True)
class LifecycleV2TransportAuthorityResolution:
    """A fully correlated structural authority/selection predecessor chain."""

    manifests: tuple[LifecycleV2TransportAuthorityManifest, ...]
    selections: tuple[LifecycleV2TransportAuthoritySelection, ...]
    selected_manifest: LifecycleV2TransportAuthorityManifest | None
    recovery_manifest: LifecycleV2TransportAuthorityManifest | None


def resolve_lifecycle_v2_transport_authority(
    manifests: tuple[LifecycleV2TransportAuthorityManifest, ...],
    selections: tuple[LifecycleV2TransportAuthoritySelection, ...],
) -> LifecycleV2TransportAuthorityResolution:
    """Validate exact generation and selection chains without trusting signatures."""

    if not manifests or not selections:
        raise TrustedTimeGracefulStopV2Rejected("transport authority chains cannot be empty")
    if any(type(item) is not LifecycleV2TransportAuthorityManifest for item in manifests):
        raise TrustedTimeGracefulStopV2Rejected("transport manifest chain type is invalid")
    if any(type(item) is not LifecycleV2TransportAuthoritySelection for item in selections):
        raise TrustedTimeGracefulStopV2Rejected("transport selection chain type is invalid")
    environment = manifests[0].environment
    root_key_id = manifests[0].root_key_id
    manifest_by_digest: dict[str, LifecycleV2TransportAuthorityManifest] = {}
    prior_key_ids: set[str] = set()
    prior_public_keys: set[bytes] = set()
    for index, manifest in enumerate(manifests, start=1):
        if (
            manifest.environment != environment
            or manifest.root_key_id != root_key_id
            or manifest.generation != index
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "transport manifest generation chain is not exact"
            )
        expected_predecessor = None if index == 1 else manifests[index - 2].sha256
        if manifest.predecessor_manifest_sha256 != expected_predecessor:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport manifest predecessor chain is not exact"
            )
        if manifest.sha256 in manifest_by_digest:
            raise TrustedTimeGracefulStopV2Rejected("duplicate transport manifest")
        generation_key_ids = {
            manifest.host_key_id,
            manifest.supervisor_key_id,
            manifest.recovery_key_id,
        }
        generation_public_keys = {
            manifest.host_public_key,
            manifest.supervisor_public_key,
            manifest.recovery_public_key,
        }
        if generation_key_ids & prior_key_ids or generation_public_keys & prior_public_keys:
            raise TrustedTimeGracefulStopV2Rejected("transport rotation reused a prior role key")
        prior_key_ids.update(generation_key_ids)
        prior_public_keys.update(generation_public_keys)
        manifest_by_digest[manifest.sha256] = manifest

    previous_selected: LifecycleV2TransportAuthorityManifest | None = None
    for index, selection in enumerate(selections, start=1):
        if selection.environment != environment or selection.sequence != index:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport authority selection chain is not exact"
            )
        expected_predecessor = None if index == 1 else selections[index - 2].sha256
        if selection.predecessor_selection_sha256 != expected_predecessor:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport selection predecessor chain is not exact"
            )
        if selection.disposition == "generation_selected":
            selected_digest = selection.selected_manifest_sha256
            selected = manifest_by_digest.get(selected_digest or "")
            if selected is None or selected.generation != selection.selected_generation:
                raise TrustedTimeGracefulStopV2Rejected(
                    "transport selection does not bind an installed manifest"
                )
            if previous_selected is None:
                if selected.generation != 1:
                    raise TrustedTimeGracefulStopV2Rejected(
                        "initial transport selection must choose generation one"
                    )
            elif selected.sha256 != previous_selected.sha256 and (
                selected.generation != previous_selected.generation + 1
                or selected.predecessor_manifest_sha256 != previous_selected.sha256
            ):
                raise TrustedTimeGracefulStopV2Rejected(
                    "transport generation rotation skips or overlaps its predecessor"
                )
            previous_selected = selected
        recovery_digest = selection.recovery_manifest_sha256
        if recovery_digest is not None and recovery_digest not in manifest_by_digest:
            raise TrustedTimeGracefulStopV2Rejected(
                "transport recovery selection does not bind an installed manifest"
            )

    current = selections[-1]
    selected_manifest = (
        manifest_by_digest[current.selected_manifest_sha256 or ""]
        if current.disposition == "generation_selected"
        else None
    )
    recovery_manifest = (
        manifest_by_digest[current.recovery_manifest_sha256]
        if current.recovery_manifest_sha256 is not None
        else None
    )
    return LifecycleV2TransportAuthorityResolution(
        manifests=manifests,
        selections=selections,
        selected_manifest=selected_manifest,
        recovery_manifest=recovery_manifest,
    )


def lifecycle_v2_recovery_manifest_for_root(
    resolution: LifecycleV2TransportAuthorityResolution,
    *,
    root_manifest_sha256: object,
    root_generation: object,
) -> LifecycleV2TransportAuthorityManifest | None:
    """Resolve recovery signing only for the exact root-pinned generation.

    A null or different current recovery selection deliberately returns
    ``None``: retained evidence remains inspectable but no recovery write is
    authorized by the structural selection.  Signature authentication remains
    the adapter's separate responsibility.
    """

    if type(resolution) is not LifecycleV2TransportAuthorityResolution:
        raise TrustedTimeGracefulStopV2Rejected("transport authority resolution is invalid")
    digest = _require_sha256(root_manifest_sha256, "root_manifest_sha256")
    generation = _require_int(root_generation, "root_generation", minimum=1)
    recovery = resolution.recovery_manifest
    if recovery is None or recovery.sha256 != digest:
        return None
    if recovery.generation != generation:
        raise TrustedTimeGracefulStopV2Rejected(
            "root-pinned recovery generation disagrees with its manifest"
        )
    return recovery


def lifecycle_v2_boot_epoch_sha256(boot_uuid: object) -> str:
    """Hash one already stable-read canonical Linux boot UUID."""

    if type(boot_uuid) is not str or _UUID.fullmatch(boot_uuid) is None:
        raise TrustedTimeGracefulStopV2Rejected("boot UUID is not canonical lowercase text")
    return _sha256(_domain_bytes(BOOT_EPOCH_DIGEST_DOMAIN, boot_uuid.encode("ascii")))


_PROCESS_EPOCH_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "role",
        "boot_epoch_sha256",
        "pid",
        "start_time_ticks",
        "pid_namespace_inode",
        "executable_path",
        "executable_sha256",
        "import_manifest_sha256",
        "process_nonce_base64",
        "container_id",
        "image_id",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2ProcessEpoch:
    fields: FrozenJsonObject
    process_nonce: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("process epochs require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _PROCESS_EPOCH_FIELDS)
        if (
            fields["contract_version"] != PROCESS_EPOCH_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "process_epoch_bound"
        ):
            raise TrustedTimeGracefulStopV2Rejected("process epoch discriminator is invalid")
        _require_identifier(fields["environment"], "environment")
        role = fields["role"]
        if role not in {"host", "supervisor"}:
            raise TrustedTimeGracefulStopV2Rejected("process epoch role is invalid")
        _require_sha256(fields["boot_epoch_sha256"], "boot_epoch_sha256")
        _require_int(fields["pid"], "pid", minimum=1)
        _require_int(fields["start_time_ticks"], "start_time_ticks", minimum=1)
        _require_int(fields["pid_namespace_inode"], "pid_namespace_inode", minimum=1)
        _require_absolute_path(fields["executable_path"], "executable_path")
        _require_sha256(fields["executable_sha256"], "executable_sha256")
        _require_sha256(fields["import_manifest_sha256"], "import_manifest_sha256")
        nonce = _require_canonical_base64(
            fields["process_nonce_base64"], "process_nonce_base64", exact_length=32
        )
        if role == "host":
            if fields["container_id"] is not None or fields["image_id"] is not None:
                raise TrustedTimeGracefulStopV2Rejected(
                    "host process epoch cannot claim a container identity"
                )
        elif (
            type(fields["container_id"]) is not str
            or _CONTAINER_ID.fullmatch(fields["container_id"]) is None
            or type(fields["image_id"]) is not str
            or _IMAGE_ID.fullmatch(fields["image_id"]) is None
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "supervisor process epoch container identity is invalid"
            )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "process_nonce", nonce)
        if len(result.encoded) > PROCESS_EPOCH_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("process epoch is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=PROCESS_EPOCH_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _domain_sha256(PROCESS_EPOCH_DIGEST_DOMAIN, self.encoded)

    @property
    def role(self) -> str:
        return self.to_dict()["role"]  # type: ignore[return-value]

    @property
    def environment(self) -> str:
        return self.to_dict()["environment"]  # type: ignore[return-value]

    @property
    def boot_epoch_sha256(self) -> str:
        return self.to_dict()["boot_epoch_sha256"]  # type: ignore[return-value]


def decode_lifecycle_v2_process_epoch(encoded: object) -> LifecycleV2ProcessEpoch:
    return LifecycleV2ProcessEpoch.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=PROCESS_EPOCH_MAXIMUM_BYTES)
    )


_PEER_CREDENTIAL_FIELDS = frozenset(
    {
        "observer_role",
        "peer_uid",
        "peer_gid",
        "peer_pid_disposition",
        "peer_pid",
        "peer_start_time_ticks",
        "peer_pid_namespace_inode",
        "peer_namespace_pid",
        "peer_container_id",
        "peer_image_id",
        "peer_executable_sha256",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2PeerCredential:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("peer credentials require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _PEER_CREDENTIAL_FIELDS)
        role = fields["observer_role"]
        disposition = fields["peer_pid_disposition"]
        uid = _require_int(fields["peer_uid"], "peer_uid", maximum=MAXIMUM_UID_GID)
        gid = _require_int(fields["peer_gid"], "peer_gid", maximum=MAXIMUM_UID_GID)
        if role == "host" and disposition == "host_visible_supervisor":
            if uid != 10_001 or gid != 10_001:
                raise TrustedTimeGracefulStopV2Rejected(
                    "host peer credentials must identify the supervisor UID/GID"
                )
            for name in (
                "peer_pid",
                "peer_start_time_ticks",
                "peer_pid_namespace_inode",
                "peer_namespace_pid",
            ):
                _require_int(fields[name], name, minimum=1)
            if (
                type(fields["peer_container_id"]) is not str
                or _CONTAINER_ID.fullmatch(fields["peer_container_id"]) is None
                or type(fields["peer_image_id"]) is not str
                or _IMAGE_ID.fullmatch(fields["peer_image_id"]) is None
            ):
                raise TrustedTimeGracefulStopV2Rejected(
                    "host peer observation container identity is invalid"
                )
            _require_sha256(fields["peer_executable_sha256"], "peer_executable_sha256")
        elif role == "supervisor" and disposition == "host_outside_private_pid_namespace":
            if uid != 0 or gid != 0 or fields["peer_pid"] != 0:
                raise TrustedTimeGracefulStopV2Rejected(
                    "supervisor peer credentials must use exact host PID-zero semantics"
                )
            for name in (
                "peer_start_time_ticks",
                "peer_pid_namespace_inode",
                "peer_namespace_pid",
                "peer_container_id",
                "peer_image_id",
                "peer_executable_sha256",
            ):
                if fields[name] is not None:
                    raise TrustedTimeGracefulStopV2Rejected(
                        "unobservable supervisor peer field must be null"
                    )
        else:
            raise TrustedTimeGracefulStopV2Rejected("peer credential disposition is invalid")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        if len(result.encoded) > IDENTITY_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("peer credential is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=IDENTITY_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _domain_sha256(PEER_CREDENTIAL_DIGEST_DOMAIN, self.encoded)


def decode_lifecycle_v2_peer_credential(encoded: object) -> LifecycleV2PeerCredential:
    return LifecycleV2PeerCredential.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=IDENTITY_MAXIMUM_BYTES)
    )


_SOCKET_IDENTITY_FIELDS = frozenset(
    {
        "observer_role",
        "absolute_path",
        "mount_id",
        "mount_parent_id",
        "mount_major_minor",
        "mount_root",
        "mount_options",
        "directory_device",
        "directory_inode",
        "directory_uid",
        "directory_gid",
        "directory_mode",
        "socket_device",
        "socket_inode",
        "socket_uid",
        "socket_gid",
        "socket_mode",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SocketIdentity:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("socket identities require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _SOCKET_IDENTITY_FIELDS)
        if fields["observer_role"] not in {"host", "supervisor"}:
            raise TrustedTimeGracefulStopV2Rejected("socket observer role is invalid")
        if fields["absolute_path"] != SUPERVISOR_SOCKET_PATH:
            raise TrustedTimeGracefulStopV2Rejected("socket path is not the fixed endpoint")
        for name in (
            "mount_id",
            "mount_parent_id",
            "directory_device",
            "directory_inode",
            "socket_device",
            "socket_inode",
        ):
            _require_int(fields[name], name, minimum=1)
        _require_identifier(fields["mount_major_minor"], "mount_major_minor")
        if type(fields["mount_root"]) is not str or not fields["mount_root"].startswith("/"):
            raise TrustedTimeGracefulStopV2Rejected("mount_root is invalid")
        mount_options = _require_sorted_options(fields["mount_options"])
        if mount_options != ("nodev", "noexec", "nosuid", "rw", "size=64K"):
            raise TrustedTimeGracefulStopV2Rejected(
                "socket transport mount options are not the fixed tmpfs profile"
            )
        for name in ("directory_uid", "directory_gid", "socket_uid", "socket_gid"):
            _require_int(fields[name], name, maximum=MAXIMUM_UID_GID)
        for name in ("directory_mode", "socket_mode"):
            _require_int(fields[name], name, maximum=0o7777)
        if (
            fields["directory_uid"] != 0
            or fields["directory_gid"] != 10_001
            or fields["directory_mode"] != 0o770
            or fields["socket_uid"] != 10_001
            or fields["socket_gid"] != 10_001
            or fields["socket_mode"] != 0o600
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "socket or transport-directory ownership is invalid"
            )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        if len(result.encoded) > IDENTITY_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("socket identity is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=IDENTITY_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        domain = (
            HOST_SOCKET_IDENTITY_DIGEST_DOMAIN
            if self.to_dict()["observer_role"] == "host"
            else SUPERVISOR_SOCKET_IDENTITY_DIGEST_DOMAIN
        )
        return _domain_sha256(domain, self.encoded)


def decode_lifecycle_v2_socket_identity(encoded: object) -> LifecycleV2SocketIdentity:
    return LifecycleV2SocketIdentity.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=IDENTITY_MAXIMUM_BYTES)
    )


_HOST_HELLO_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2HostHello:
    fields: FrozenJsonObject
    signature: bytes
    host_process_epoch: LifecycleV2ProcessEpoch
    host_challenge: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("host hellos require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _HOST_HELLO_FIELDS)
        if (
            fields["contract_version"] != HOST_HELLO_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "host_hello_offered"
            or fields["protocol_version"] != TRANSPORT_PROTOCOL_VERSION
            or fields["direction"] != "host_to_supervisor"
            or fields["message_counter"] != 0
        ):
            raise TrustedTimeGracefulStopV2Rejected("host hello discriminator is invalid")
        environment = _require_identifier(fields["environment"], "environment")
        _require_identifier(fields["graceful_stop_operation_id"], "graceful_stop_operation_id")
        _require_sha256(
            fields["transport_authority_manifest_sha256"],
            "transport_authority_manifest_sha256",
        )
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        _require_identifier(fields["host_key_id"], "host_key_id")
        _require_identifier(fields["expected_supervisor_key_id"], "expected_supervisor_key_id")
        boot_digest = _require_sha256(fields["boot_epoch_sha256"], "boot_epoch_sha256")
        process_value = fields["host_process_epoch"]
        process_epoch = LifecycleV2ProcessEpoch.capture(process_value)
        if (
            process_epoch.role != "host"
            or process_epoch.environment != environment
            or process_epoch.boot_epoch_sha256 != boot_digest
            or fields["host_process_epoch_sha256"] != process_epoch.sha256
        ):
            raise TrustedTimeGracefulStopV2Rejected("host process epoch binding is invalid")
        challenge = _require_canonical_base64(
            fields["host_challenge_base64"], "host_challenge_base64", exact_length=32
        )
        _require_sha256(fields["host_socket_identity_sha256"], "host_socket_identity_sha256")
        _require_sha256(fields["host_peer_credential_sha256"], "host_peer_credential_sha256")
        _require_int(fields["handshake_deadline_boottime_ns"], "handshake_deadline_boottime_ns")
        signature = _require_canonical_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "signature", signature)
        object.__setattr__(result, "host_process_epoch", process_epoch)
        object.__setattr__(result, "host_challenge", challenge)
        if len(result.encoded) > HOST_HELLO_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("host hello is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            _unsigned_fields(self.fields), maximum_bytes=HOST_HELLO_MAXIMUM_BYTES
        )

    @property
    def signature_input(self) -> bytes:
        return _domain_bytes(HOST_HELLO_SIGNATURE_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=HOST_HELLO_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_host_hello(encoded: object) -> LifecycleV2HostHello:
    return LifecycleV2HostHello.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=HOST_HELLO_MAXIMUM_BYTES)
    )


_CHANNEL_BINDING_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "protocol_version",
        "environment",
        "graceful_stop_operation_id",
        "transport_authority_manifest_sha256",
        "key_generation",
        "host_key_id",
        "supervisor_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "host_hello_sha256",
        "host_challenge_base64",
        "supervisor_challenge_base64",
        "host_socket_identity_sha256",
        "supervisor_socket_identity_sha256",
        "host_peer_credential_sha256",
        "supervisor_peer_credential_sha256",
        "handshake_deadline_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2ChannelBinding:
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("channel bindings require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _CHANNEL_BINDING_FIELDS)
        if (
            fields["contract_version"] != CHANNEL_BINDING_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["protocol_version"] != TRANSPORT_PROTOCOL_VERSION
        ):
            raise TrustedTimeGracefulStopV2Rejected("channel binding discriminator is invalid")
        for name in (
            "environment",
            "graceful_stop_operation_id",
            "host_key_id",
            "supervisor_key_id",
        ):
            _require_identifier(fields[name], name)
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        for name in (
            "transport_authority_manifest_sha256",
            "boot_epoch_sha256",
            "host_process_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "host_hello_sha256",
            "host_socket_identity_sha256",
            "supervisor_socket_identity_sha256",
            "host_peer_credential_sha256",
            "supervisor_peer_credential_sha256",
        ):
            _require_sha256(fields[name], name)
        _require_canonical_base64(
            fields["host_challenge_base64"], "host_challenge_base64", exact_length=32
        )
        _require_canonical_base64(
            fields["supervisor_challenge_base64"],
            "supervisor_challenge_base64",
            exact_length=32,
        )
        _require_int(fields["handshake_deadline_boottime_ns"], "handshake_deadline_boottime_ns")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        if len(result.encoded) > IDENTITY_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("channel binding is too large")
        return result

    @classmethod
    def from_host_hello(
        cls,
        host_hello: LifecycleV2HostHello,
        *,
        supervisor_process_epoch: LifecycleV2ProcessEpoch,
        supervisor_key_id: str,
        supervisor_challenge_base64: str,
        supervisor_socket_identity_sha256: str,
        supervisor_peer_credential_sha256: str,
    ) -> Self:
        if type(host_hello) is not LifecycleV2HostHello:
            raise TrustedTimeGracefulStopV2Rejected("channel binding host hello is invalid")
        if (
            type(supervisor_process_epoch) is not LifecycleV2ProcessEpoch
            or supervisor_process_epoch.role != "supervisor"
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "channel binding supervisor process epoch is invalid"
            )
        host = host_hello.to_dict()
        if (
            supervisor_process_epoch.environment != host["environment"]
            or supervisor_process_epoch.boot_epoch_sha256 != host["boot_epoch_sha256"]
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "channel binding process epoch crosses environment or boot"
            )
        return cls.capture(
            {
                "contract_version": CHANNEL_BINDING_CONTRACT_VERSION,
                "service": TRANSPORT_SERVICE,
                "protocol_version": TRANSPORT_PROTOCOL_VERSION,
                "environment": host["environment"],
                "graceful_stop_operation_id": host["graceful_stop_operation_id"],
                "transport_authority_manifest_sha256": host["transport_authority_manifest_sha256"],
                "key_generation": host["key_generation"],
                "host_key_id": host["host_key_id"],
                "supervisor_key_id": supervisor_key_id,
                "boot_epoch_sha256": host["boot_epoch_sha256"],
                "host_process_epoch_sha256": host["host_process_epoch_sha256"],
                "supervisor_process_epoch_sha256": supervisor_process_epoch.sha256,
                "host_hello_sha256": host_hello.sha256,
                "host_challenge_base64": host["host_challenge_base64"],
                "supervisor_challenge_base64": supervisor_challenge_base64,
                "host_socket_identity_sha256": host["host_socket_identity_sha256"],
                "supervisor_socket_identity_sha256": supervisor_socket_identity_sha256,
                "host_peer_credential_sha256": host["host_peer_credential_sha256"],
                "supervisor_peer_credential_sha256": supervisor_peer_credential_sha256,
                "handshake_deadline_boottime_ns": host["handshake_deadline_boottime_ns"],
            }
        )

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=IDENTITY_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _domain_sha256(CHANNEL_DIGEST_DOMAIN, self.encoded)


_SUPERVISOR_HELLO_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SupervisorHello:
    fields: FrozenJsonObject
    signature: bytes
    supervisor_process_epoch: LifecycleV2ProcessEpoch
    supervisor_challenge: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("supervisor hellos require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _SUPERVISOR_HELLO_FIELDS)
        if (
            fields["contract_version"] != SUPERVISOR_HELLO_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "supervisor_hello_accepted"
            or fields["protocol_version"] != TRANSPORT_PROTOCOL_VERSION
            or fields["direction"] != "supervisor_to_host"
            or fields["message_counter"] != 0
        ):
            raise TrustedTimeGracefulStopV2Rejected("supervisor hello discriminator is invalid")
        environment = _require_identifier(fields["environment"], "environment")
        _require_identifier(fields["graceful_stop_operation_id"], "graceful_stop_operation_id")
        _require_sha256(
            fields["transport_authority_manifest_sha256"],
            "transport_authority_manifest_sha256",
        )
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        _require_identifier(fields["host_key_id"], "host_key_id")
        _require_identifier(fields["supervisor_key_id"], "supervisor_key_id")
        boot_digest = _require_sha256(fields["boot_epoch_sha256"], "boot_epoch_sha256")
        for name in (
            "host_hello_sha256",
            "host_process_epoch_sha256",
            "host_socket_identity_sha256",
            "supervisor_socket_identity_sha256",
            "host_peer_credential_sha256",
            "supervisor_peer_credential_sha256",
            "channel_id",
        ):
            _require_sha256(fields[name], name)
        process_epoch = LifecycleV2ProcessEpoch.capture(fields["supervisor_process_epoch"])
        if (
            process_epoch.role != "supervisor"
            or process_epoch.environment != environment
            or process_epoch.boot_epoch_sha256 != boot_digest
            or fields["supervisor_process_epoch_sha256"] != process_epoch.sha256
        ):
            raise TrustedTimeGracefulStopV2Rejected("supervisor process epoch binding is invalid")
        _require_canonical_base64(
            fields["host_challenge_base64"], "host_challenge_base64", exact_length=32
        )
        supervisor_challenge = _require_canonical_base64(
            fields["supervisor_challenge_base64"],
            "supervisor_challenge_base64",
            exact_length=32,
        )
        _require_int(fields["handshake_deadline_boottime_ns"], "handshake_deadline_boottime_ns")
        signature = _require_canonical_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "signature", signature)
        object.__setattr__(result, "supervisor_process_epoch", process_epoch)
        object.__setattr__(result, "supervisor_challenge", supervisor_challenge)
        if len(result.encoded) > SUPERVISOR_HELLO_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("supervisor hello is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            _unsigned_fields(self.fields), maximum_bytes=SUPERVISOR_HELLO_MAXIMUM_BYTES
        )

    @property
    def signature_input(self) -> bytes:
        return _domain_bytes(SUPERVISOR_HELLO_SIGNATURE_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=SUPERVISOR_HELLO_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_supervisor_hello(encoded: object) -> LifecycleV2SupervisorHello:
    return LifecycleV2SupervisorHello.capture(
        decode_canonical_v2_json_object(encoded, maximum_bytes=SUPERVISOR_HELLO_MAXIMUM_BYTES)
    )


_HOST_CONFIRMATION_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2HostChannelConfirmation:
    fields: FrozenJsonObject
    signature: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("host channel confirmations require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _HOST_CONFIRMATION_FIELDS)
        if (
            fields["contract_version"] != HOST_CHANNEL_CONFIRMATION_CONTRACT_VERSION
            or fields["service"] != TRANSPORT_SERVICE
            or fields["status"] != "host_channel_confirmed"
            or fields["protocol_version"] != TRANSPORT_PROTOCOL_VERSION
            or fields["direction"] != "host_to_supervisor"
            or fields["message_counter"] != 1
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "host channel confirmation discriminator is invalid"
            )
        for name in (
            "environment",
            "graceful_stop_operation_id",
            "host_key_id",
            "supervisor_key_id",
        ):
            _require_identifier(fields[name], name)
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        for name in (
            "transport_authority_manifest_sha256",
            "boot_epoch_sha256",
            "host_hello_sha256",
            "supervisor_hello_sha256",
            "host_process_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "channel_id",
        ):
            _require_sha256(fields[name], name)
        _require_int(fields["handshake_deadline_boottime_ns"], "handshake_deadline_boottime_ns")
        signature = _require_canonical_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "signature", signature)
        if len(result.encoded) > HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected("host channel confirmation is too large")
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            _unsigned_fields(self.fields),
            maximum_bytes=HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES,
        )

    @property
    def signature_input(self) -> bytes:
        return _domain_bytes(HOST_CHANNEL_CONFIRMATION_SIGNATURE_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(), maximum_bytes=HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)


def decode_lifecycle_v2_host_channel_confirmation(
    encoded: object,
) -> LifecycleV2HostChannelConfirmation:
    return LifecycleV2HostChannelConfirmation.capture(
        decode_canonical_v2_json_object(
            encoded, maximum_bytes=HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES
        )
    )


@dataclass(frozen=True, slots=True)
class LifecycleV2Handshake:
    host_hello: LifecycleV2HostHello
    supervisor_hello: LifecycleV2SupervisorHello
    host_confirmation: LifecycleV2HostChannelConfirmation
    channel_binding: LifecycleV2ChannelBinding

    @property
    def channel_id(self) -> str:
        return self.channel_binding.sha256


def bind_lifecycle_v2_handshake(
    host_hello: LifecycleV2HostHello,
    supervisor_hello: LifecycleV2SupervisorHello,
    host_confirmation: LifecycleV2HostChannelConfirmation,
) -> LifecycleV2Handshake:
    """Correlate three structurally decoded handshake messages exactly."""

    if (
        type(host_hello) is not LifecycleV2HostHello
        or type(supervisor_hello) is not LifecycleV2SupervisorHello
        or type(host_confirmation) is not LifecycleV2HostChannelConfirmation
    ):
        raise TrustedTimeGracefulStopV2Rejected("handshake values must be exact")
    host = host_hello.to_dict()
    supervisor = supervisor_hello.to_dict()
    confirmation = host_confirmation.to_dict()
    repeated = (
        "environment",
        "graceful_stop_operation_id",
        "transport_authority_manifest_sha256",
        "key_generation",
        "host_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "handshake_deadline_boottime_ns",
    )
    if any(supervisor[name] != host[name] for name in repeated):
        raise TrustedTimeGracefulStopV2Rejected("supervisor hello crosses host hello identity")
    if host["expected_supervisor_key_id"] != supervisor["supervisor_key_id"]:
        raise TrustedTimeGracefulStopV2Rejected("supervisor hello uses an unexpected key")
    if (
        supervisor["host_hello_sha256"] != host_hello.sha256
        or supervisor["host_challenge_base64"] != host["host_challenge_base64"]
        or supervisor["host_socket_identity_sha256"] != host["host_socket_identity_sha256"]
        or supervisor["host_peer_credential_sha256"] != host["host_peer_credential_sha256"]
    ):
        raise TrustedTimeGracefulStopV2Rejected("supervisor hello does not bind host hello")
    channel_binding = LifecycleV2ChannelBinding.from_host_hello(
        host_hello,
        supervisor_process_epoch=supervisor_hello.supervisor_process_epoch,
        supervisor_key_id=supervisor["supervisor_key_id"],  # type: ignore[arg-type]
        supervisor_challenge_base64=supervisor["supervisor_challenge_base64"],  # type: ignore[arg-type]
        supervisor_socket_identity_sha256=supervisor["supervisor_socket_identity_sha256"],  # type: ignore[arg-type]
        supervisor_peer_credential_sha256=supervisor["supervisor_peer_credential_sha256"],  # type: ignore[arg-type]
    )
    if supervisor["channel_id"] != channel_binding.sha256:
        raise TrustedTimeGracefulStopV2Rejected("supervisor hello channel digest is invalid")
    confirmation_repeated = (
        "environment",
        "graceful_stop_operation_id",
        "transport_authority_manifest_sha256",
        "key_generation",
        "host_key_id",
        "supervisor_key_id",
        "boot_epoch_sha256",
        "host_process_epoch_sha256",
        "supervisor_process_epoch_sha256",
        "channel_id",
        "handshake_deadline_boottime_ns",
    )
    if any(confirmation[name] != supervisor[name] for name in confirmation_repeated):
        raise TrustedTimeGracefulStopV2Rejected(
            "host channel confirmation crosses supervisor hello identity"
        )
    if (
        confirmation["host_hello_sha256"] != host_hello.sha256
        or confirmation["supervisor_hello_sha256"] != supervisor_hello.sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "host channel confirmation does not bind both hellos"
        )
    return LifecycleV2Handshake(
        host_hello=host_hello,
        supervisor_hello=supervisor_hello,
        host_confirmation=host_confirmation,
        channel_binding=channel_binding,
    )


def lifecycle_v2_transport_contract_non_authority_facts() -> dict[str, bool]:
    return {
        "production_caller_present": False,
        "installed_authority_reader_present": False,
        "boot_reader_present": False,
        "process_reader_present": False,
        "socket_endpoint_present": False,
        "private_key_owner_present": False,
        "transport_dispatch_present": False,
        "stop_effect_authorized": False,
    }


__all__ = [
    "AUTHORITY_MAXIMUM_BYTES",
    "CHANNEL_BINDING_CONTRACT_VERSION",
    "HOST_CHANNEL_CONFIRMATION_CONTRACT_VERSION",
    "HOST_CHANNEL_CONFIRMATION_MAXIMUM_BYTES",
    "HOST_HELLO_CONTRACT_VERSION",
    "HOST_HELLO_MAXIMUM_BYTES",
    "PROCESS_EPOCH_CONTRACT_VERSION",
    "SUPERVISOR_HELLO_CONTRACT_VERSION",
    "SUPERVISOR_HELLO_MAXIMUM_BYTES",
    "SUPERVISOR_SOCKET_PATH",
    "TRANSPORT_AUTHORITY_MANIFEST_CONTRACT_VERSION",
    "TRANSPORT_AUTHORITY_SELECTION_CONTRACT_VERSION",
    "TRANSPORT_PROTOCOL_VERSION",
    "TRANSPORT_SERVICE",
    "LifecycleV2ChannelBinding",
    "LifecycleV2Handshake",
    "LifecycleV2HostChannelConfirmation",
    "LifecycleV2HostHello",
    "LifecycleV2PeerCredential",
    "LifecycleV2ProcessEpoch",
    "LifecycleV2SocketIdentity",
    "LifecycleV2SupervisorHello",
    "LifecycleV2TransportAuthorityManifest",
    "LifecycleV2TransportAuthorityResolution",
    "LifecycleV2TransportAuthoritySelection",
    "bind_lifecycle_v2_handshake",
    "decode_lifecycle_v2_host_channel_confirmation",
    "decode_lifecycle_v2_host_hello",
    "decode_lifecycle_v2_peer_credential",
    "decode_lifecycle_v2_process_epoch",
    "decode_lifecycle_v2_socket_identity",
    "decode_lifecycle_v2_supervisor_hello",
    "decode_lifecycle_v2_transport_authority_manifest",
    "decode_lifecycle_v2_transport_authority_selection",
    "lifecycle_v2_boot_epoch_sha256",
    "lifecycle_v2_recovery_manifest_for_root",
    "lifecycle_v2_transport_contract_non_authority_facts",
    "resolve_lifecycle_v2_transport_authority",
]
