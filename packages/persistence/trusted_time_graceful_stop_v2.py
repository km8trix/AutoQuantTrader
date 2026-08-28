"""Injected-root lifecycle-v2 repository for ADR 0121 milestone-one core.

The repository owns ordering and namespace validation while all physical
authority remains behind an explicitly injected, descriptor-safe store.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_COMMIT_BUDGET_NS,
    LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
    LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
    LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    LIFECYCLE_V2_SERVICE,
    MAXIMUM_SIGNED_INTEGER,
    NORMAL_STAGE_BY_ORDINAL,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2Outcome,
    LifecycleV2OutcomeCommit,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    LifecycleV2TranscriptEntry,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    _FakeAuthenticatedLifecycleV2TransportEnvelope,
    _require_fake_authenticated_lifecycle_v2_transport_envelope,
    decode_lifecycle_v2_clean_stop_request_basis,
    decode_lifecycle_v2_outcome,
    decode_lifecycle_v2_outcome_commit,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    decode_unverified_lifecycle_v2_transport_envelope,
    lifecycle_v2_dispatch_prefix_sha256,
    lifecycle_v2_progress_file_name,
    lifecycle_v2_wire_file_name,
)
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    LifecycleV2ConfirmedSuccessLineageSnapshot,
    LifecycleV2NormalProgressLineage,
    TrustedTimeLifecycleV2SemanticsRejected,
    consume_exact_lifecycle_v2_confirmed_success_lineage,
    consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository,
)
from packages.domain.trusted_time_graceful_stop_v2_recovery import (
    LifecycleV2AuthenticatedRecoveryIntent,
    consume_authenticated_lifecycle_v2_recovery_intent,
    require_authenticated_lifecycle_v2_recovery_intent,
)

_V1_ROOT_CONTRACT_VERSION = "phase6d-post-enrollment-graceful-stop-attempt-v1"
_ROOT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-root-staging"
_RECORD_STAGING_NAME = ".post-enrollment-graceful-stop-v2-record-staging"
_TRANSCRIPT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-transcript-staging"
_WIRE_RESULT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-wire-result-staging"
_WIRE_ERROR_STAGING_NAME = ".post-enrollment-graceful-stop-v2-wire-error-staging"
_OUTCOME_STAGING_NAME = ".post-enrollment-graceful-stop-v2-outcome-staging"
_COMMIT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-outcome-commit-staging"
_STAGING_NAMES = frozenset(
    {
        _ROOT_STAGING_NAME,
        _RECORD_STAGING_NAME,
        _TRANSCRIPT_STAGING_NAME,
        _WIRE_RESULT_STAGING_NAME,
        _WIRE_ERROR_STAGING_NAME,
        _OUTCOME_STAGING_NAME,
        _COMMIT_STAGING_NAME,
    }
)
_MAXIMUM_INVENTORY_ENTRIES = 128
_MAXIMUM_INVENTORY_NAME_BYTES = 32 * 1_024


class LifecycleV2RepositoryRejected(RuntimeError):
    """The injected repository invocation or durable transition was rejected."""


class LifecycleV2SlotConsumed(LifecycleV2RepositoryRejected):
    """The one v1/v2 lifecycle root is already consumed."""


class LifecycleV2RetentionUnconfirmed(LifecycleV2RepositoryRejected):
    """Storage may have changed and only incident-preserving inspection is safe."""


class LifecycleV2ArtifactAlreadyExists(RuntimeError):
    """The injected no-replace store found an existing name."""


class LifecycleV2ArtifactPublicationUncertain(RuntimeError):
    """An injected publication failed before its durable result was knowable."""


class LifecycleV2RepositoryStatus(StrEnum):
    UNRESERVED = "unreserved"
    ROOT_RESERVED = "root_reserved"
    RECOVERY_REQUIRED = "recovery_required"
    OUTCOME_COMMIT_UNCONFIRMED = "outcome_commit_unconfirmed"
    OUTCOME_COMMITTED = "outcome_committed"
    RETENTION_UNCONFIRMED = "retention_unconfirmed"


@dataclass(frozen=True, slots=True)
class LifecycleV2ArtifactStoreIdentity:
    """Canonical immutable identity of one injected artifact directory."""

    artifact_directory_path: str
    directory_device: int
    directory_inode: int
    owner_uid: int
    owner_gid: int
    directory_mode: int

    def __post_init__(self) -> None:
        _safe_artifact_directory_path(self.artifact_directory_path)
        for name in ("directory_device", "directory_inode"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be one exact positive integer")
        for name in ("owner_uid", "owner_gid"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be one exact nonnegative integer")
        if type(self.directory_mode) is not int or self.directory_mode != 0o700:
            raise ValueError("artifact directory mode must be exactly 0700")


@dataclass(frozen=True, slots=True)
class LifecycleV2ArtifactInventorySnapshot:
    """One bounded directory inventory and its exact native stability token."""

    names: tuple[str, ...]
    directory_token: tuple[int, int, int, int, int, int, int, int, int]

    def __post_init__(self) -> None:
        if (
            type(self.names) is not tuple
            or any(type(name) is not str for name in self.names)
            or self.names != tuple(sorted(self.names))
            or len(self.names) != len(frozenset(self.names))
        ):
            raise ValueError("artifact inventory names are not exact, sorted, and unique")
        if (
            type(self.directory_token) is not tuple
            or len(self.directory_token) != 9
            or any(type(field) is not int for field in self.directory_token)
        ):
            raise ValueError("artifact inventory token is not one exact native identity")


@dataclass(frozen=True, slots=True)
class LifecycleV2ArtifactReadback:
    """Stable no-follow bytes and exact identity of one immutable artifact."""

    encoded: bytes
    file_device: int
    file_inode: int
    file_mode: int
    file_size: int
    stable_readback_completed: bool

    def __post_init__(self) -> None:
        if type(self.encoded) is not bytes:
            raise ValueError("artifact readback bytes are not exact")
        for name in ("file_device", "file_inode", "file_size"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be one exact positive integer")
        if self.file_size != len(self.encoded):
            raise ValueError("artifact readback size disagrees with its bytes")
        if type(self.file_mode) is not int or self.file_mode != 0o600:
            raise ValueError("artifact readback mode must be exactly 0600")
        if self.stable_readback_completed is not True:
            raise ValueError("artifact readback is not complete")


@dataclass(frozen=True, slots=True)
class LifecycleV2ArtifactPublicationReceipt:
    """Exact physical result of one create or immutable publication attempt."""

    final_name: str
    final_device: int
    final_inode: int
    final_mode: int
    final_size: int
    file_fsync_completed: bool
    no_replace_rename_completed: bool
    directory_fsync_completed: bool
    stable_readback_completed: bool
    existing_final_revalidated: bool

    def __post_init__(self) -> None:
        if (
            type(self.final_name) is not str
            or not self.final_name
            or self.final_name in {".", ".."}
            or "/" in self.final_name
            or "\0" in self.final_name
        ):
            raise ValueError("publication receipt final name is invalid")
        for name in ("final_device", "final_inode", "final_size"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be one exact positive integer")
        if type(self.final_mode) is not int or self.final_mode != 0o600:
            raise ValueError("publication receipt mode must be exactly 0600")
        for name in (
            "file_fsync_completed",
            "no_replace_rename_completed",
            "directory_fsync_completed",
            "stable_readback_completed",
            "existing_final_revalidated",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be one exact boolean")
        if self.stable_readback_completed is not True:
            raise ValueError("publication receipt lacks stable readback")
        if not self.file_fsync_completed or not self.directory_fsync_completed:
            raise ValueError("publication receipt lacks required fsync completion")
        if self.existing_final_revalidated and self.no_replace_rename_completed:
            raise ValueError("existing-final revalidation cannot claim a new rename")


class LifecycleV2ArtifactStore(Protocol):
    """Injected storage seam with no default root or production caller."""

    @property
    def identity(self) -> LifecycleV2ArtifactStoreIdentity: ...

    def inventory(self) -> LifecycleV2ArtifactInventorySnapshot: ...

    def read_stable(self, file_name: str) -> LifecycleV2ArtifactReadback: ...

    def create_root_exclusive(
        self,
        file_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt: ...

    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt: ...

    def finalize_preallocated_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> LifecycleV2ArtifactPublicationReceipt: ...

    def close(self) -> None: ...


class LifecycleV2AuthenticatedRetainedWireResult(Protocol):
    """Read-only view opened from one verifier-owned sealed authentication result."""

    @property
    def envelope(self) -> UnverifiedLifecycleV2TransportEnvelope: ...

    @property
    def authority_manifest_sha256(self) -> str: ...

    @property
    def signer_role(self) -> str: ...

    @property
    def root_sha256(self) -> str: ...

    @property
    def request_intent_sha256(self) -> str: ...

    @property
    def terminal_record_sha256(self) -> str: ...

    @property
    def artifact_directory_path(self) -> str: ...


class LifecycleV2RetainedWireVerifier(Protocol):
    """Injected authenticator that owns and reopens its exact sealed result."""

    def reauthenticate_retained_terminal_wire(
        self,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        root: LifecycleV2Root,
        request_intent: LifecycleV2ProgressRecord,
        terminal_record: LifecycleV2ProgressRecord,
        artifact_directory_path: str,
    ) -> object: ...

    def require_exact_authenticated_retained_terminal_wire(
        self,
        result: object,
    ) -> LifecycleV2AuthenticatedRetainedWireResult: ...


class LifecycleV2BoottimeClock(Protocol):
    """Injected exact CLOCK_BOOTTIME source; no wall-clock fallback exists."""

    def sample_boottime_ns(self) -> int: ...


class LifecycleV2SuccessPrecommitDisposition(Protocol):
    """Read-only view of one verifier-owned, sealed empty-owner result."""

    @property
    def root_sha256(self) -> str: ...

    @property
    def transcript_sha256(self) -> str: ...

    @property
    def outcome_sha256(self) -> str: ...

    @property
    def candidate_handle_disposed(self) -> bool: ...

    @property
    def transcript_handle_disposed(self) -> bool: ...

    @property
    def transient_descriptor_count(self) -> int: ...

    @property
    def registry_entry_count(self) -> int: ...


class LifecycleV2SuccessPrecommitDisposer(Protocol):
    """Injected owner that disposes candidate/transcript handles and proves emptiness."""

    def dispose_and_prove_empty(
        self,
        *,
        root: LifecycleV2Root,
        transcript: LifecycleV2Transcript,
        outcome: LifecycleV2Outcome,
        artifact_store_identity: LifecycleV2ArtifactStoreIdentity,
    ) -> object: ...

    def require_exact_disposed_and_empty(
        self,
        result: object,
    ) -> LifecycleV2SuccessPrecommitDisposition: ...


@dataclass(frozen=True, slots=True, init=False)
class _LifecycleV2OutcomeCommitMarkerBasis:
    """Prevalidated marker bytes with only the boottime integer left absent."""

    outcome: LifecycleV2Outcome
    prefix: bytes
    suffix: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fixed-marker bases require exact preallocation")

    @classmethod
    def prepare(cls, outcome: LifecycleV2Outcome) -> _LifecycleV2OutcomeCommitMarkerBasis:
        try:
            exact_outcome = decode_lifecycle_v2_outcome(outcome.encoded)
        except (AttributeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected(
                "outcome candidate is not canonical for marker preallocation"
            ) from None
        if exact_outcome != outcome:
            raise LifecycleV2RepositoryRejected(
                "outcome candidate changed during marker preallocation"
            )
        fields = exact_outcome.to_dict()
        protocol_start = cast(int, fields["commit_protocol_started_boottime_ns"])
        authorized = fields["commit_authorized_boottime_ns"]
        placeholder = protocol_start if authorized is None else cast(int, authorized)
        marker_fields: dict[str, object] = {
            "contract_version": LIFECYCLE_V2_OUTCOME_COMMIT_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "terminal_outcome_committed",
            "lifecycle_version": 2,
            "graceful_stop_operation_id": fields["graceful_stop_operation_id"],
            "root_sha256": fields["root_sha256"],
            "outcome_sha256": exact_outcome.sha256,
            "outcome_status": fields["status"],
            "transcript_sha256": fields["transcript_sha256"],
            "admission_started_boottime_ns": fields["admission_started_boottime_ns"],
            "commit_protocol_started_boottime_ns": protocol_start,
            "commit_publication_authorization_deadline_boottime_ns": fields[
                "commit_publication_authorization_deadline_boottime_ns"
            ],
            "commit_authorized_boottime_ns": placeholder,
            "operation_deadline_boottime_ns": fields["operation_deadline_boottime_ns"],
            # Audit-only and deterministic across restart: the candidate fixes it.
            "committed_at_utc": fields["created_at_utc"],
        }
        marker = LifecycleV2OutcomeCommit.capture(marker_fields, outcome=exact_outcome)
        needle = b'"commit_authorized_boottime_ns":' + str(placeholder).encode("ascii")
        if marker.encoded.count(needle) != 1:
            raise LifecycleV2RepositoryRejected("fixed-marker authorization slot is not unique")
        prefix, suffix = marker.encoded.split(needle, 1)
        result = object.__new__(cls)
        object.__setattr__(result, "outcome", exact_outcome)
        object.__setattr__(
            result,
            "prefix",
            prefix + b'"commit_authorized_boottime_ns":',
        )
        object.__setattr__(result, "suffix", suffix)
        return result

    def materialize(self, commit_authorized_boottime_ns: int) -> bytes:
        """Mechanically fill the sole absent integer; perform no lookup or I/O."""

        return self.prefix + str(commit_authorized_boottime_ns).encode("ascii") + self.suffix


def _safe_artifact_directory_path(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or not value.endswith("/trusted-time")
        or value == "/trusted-time"
        or "//" in value
        or "/../" in value
        or "/./" in value
        or "\0" in value
        or len(value.encode("utf-8")) > 4_096
    ):
        raise LifecycleV2RepositoryRejected("artifact directory path is not exact")
    return value


def _safe_artifact_store_identity(value: object) -> LifecycleV2ArtifactStoreIdentity:
    if type(value) is not LifecycleV2ArtifactStoreIdentity:
        raise LifecycleV2RepositoryRejected("artifact-store identity type is not exact")
    try:
        verified = LifecycleV2ArtifactStoreIdentity(
            artifact_directory_path=value.artifact_directory_path,
            directory_device=value.directory_device,
            directory_inode=value.directory_inode,
            owner_uid=value.owner_uid,
            owner_gid=value.owner_gid,
            directory_mode=value.directory_mode,
        )
    except (AttributeError, TypeError, ValueError):
        raise LifecycleV2RepositoryRejected("artifact-store identity is not canonical") from None
    if verified != value:
        raise LifecycleV2RepositoryRejected("artifact-store identity changed under validation")
    return verified


def _contract_version(encoded: bytes) -> object:
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if type(value) is not dict:
        return None
    return value.get("contract_version")


def _known_v2_name(name: str) -> bool:
    return (
        name in (LIFECYCLE_ROOT_FILE_NAME, LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME)
        or name in _STAGING_NAMES
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-record-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-transcript-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-result-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-error-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-outcome-")
    )


class _LifecycleV2Repository:
    """One process/thread-bound repository over an explicitly injected store."""

    __slots__ = (
        "_artifact_directory_path",
        "_closed",
        "_commit",
        "_commit_staging",
        "_opened_with_existing_root",
        "_origin_pid",
        "_origin_thread",
        "_outcome",
        "_poisoned",
        "_records",
        "_retained_wire_verifier",
        "_root",
        "_store",
        "_store_disposed",
        "_store_identity",
        "_wire",
    )

    def __init__(
        self,
        store: LifecycleV2ArtifactStore,
        *,
        artifact_directory_path: str | None,
        retained_wire_verifier: LifecycleV2RetainedWireVerifier | None,
    ) -> None:
        self._store = store
        self._retained_wire_verifier = retained_wire_verifier
        self._origin_pid = os.getpid()
        self._origin_thread = threading.current_thread()
        self._poisoned = False
        self._closed = False
        self._store_disposed = False
        self._opened_with_existing_root = False
        self._root: LifecycleV2Root | None = None
        self._records: tuple[LifecycleV2ProgressRecord, ...] = ()
        self._wire: UnverifiedLifecycleV2TransportEnvelope | None = None
        self._outcome: LifecycleV2Outcome | None = None
        self._commit: LifecycleV2OutcomeCommit | None = None
        self._commit_staging: LifecycleV2OutcomeCommit | None = None
        try:
            identity = _safe_artifact_store_identity(store.identity)
            if (
                artifact_directory_path is not None
                and _safe_artifact_directory_path(artifact_directory_path)
                != identity.artifact_directory_path
            ):
                raise LifecycleV2RepositoryRejected(
                    "artifact directory path duplicates the store identity incorrectly"
                )
        except BaseException:
            with suppress(Exception):
                store.close()
            raise
        self._store_identity = identity
        self._artifact_directory_path = identity.artifact_directory_path
        self._load_namespace()

    def _require_origin(self) -> None:
        if os.getpid() != self._origin_pid or threading.current_thread() is not self._origin_thread:
            raise LifecycleV2RetentionUnconfirmed("repository process or thread owner is invalid")

    def _require_store_binding(self) -> None:
        try:
            identity = _safe_artifact_store_identity(self._store.identity)
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "artifact-store identity is unavailable"
            ) from None
        if identity != self._store_identity:
            self._burn()
            raise LifecycleV2RetentionUnconfirmed("artifact-store identity changed")

    def _require_owner(self) -> None:
        self._require_origin()
        if self._closed:
            raise LifecycleV2RetentionUnconfirmed("repository is closed")
        self._require_store_binding()
        if self._poisoned:
            raise LifecycleV2RetentionUnconfirmed("repository owner is burned")

    def _burn(self) -> None:
        self._poisoned = True
        if not self._store_disposed:
            self._store_disposed = True
            with suppress(Exception):
                self._store.close()

    def close(self) -> None:
        """Dispose the repository once from its exact origin process and thread."""

        self._require_origin()
        if self._closed:
            return
        if self._store_disposed:
            self._closed = True
            return
        self._store_disposed = True
        try:
            self._store.close()
        except BaseException as error:
            self._poisoned = True
            self._closed = True
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("repository disposal is unconfirmed") from None
        self._closed = True

    def __enter__(self) -> _LifecycleV2Repository:
        self._require_owner()
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self._require_origin()
        self.close()

    @property
    def artifact_store_identity(self) -> LifecycleV2ArtifactStoreIdentity:
        self._require_owner()
        return self._store_identity

    def _inventory(self) -> LifecycleV2ArtifactInventorySnapshot:
        snapshot = self._store.inventory()
        if type(snapshot) is not LifecycleV2ArtifactInventorySnapshot:
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact inventory snapshot type is not exact"
            )
        try:
            name_bytes = tuple(name.encode("utf-8") for name in snapshot.names)
        except UnicodeEncodeError:
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact inventory name encoding is invalid"
            ) from None
        if (
            len(snapshot.names) > _MAXIMUM_INVENTORY_ENTRIES
            or sum(map(len, name_bytes)) > _MAXIMUM_INVENTORY_NAME_BYTES
            or any(
                name in {"", ".", ".."} or "/" in name or "\0" in name or len(encoded) > 255
                for name, encoded in zip(snapshot.names, name_bytes, strict=True)
            )
        ):
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact inventory is not one bounded component namespace"
            )
        token = snapshot.directory_token
        if (token[0], token[1], token[2] & 0o7777, token[3], token[4]) != (
            self._store_identity.directory_device,
            self._store_identity.directory_inode,
            self._store_identity.directory_mode,
            self._store_identity.owner_uid,
            self._store_identity.owner_gid,
        ) or token[5] < 1:
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact inventory token crossed the injected directory identity"
            )
        return snapshot

    def _read_artifact(self, file_name: str) -> LifecycleV2ArtifactReadback:
        readback = self._store.read_stable(file_name)
        if (
            type(readback) is not LifecycleV2ArtifactReadback
            or readback.file_device != self._store_identity.directory_device
        ):
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact stable readback identity is not exact"
            )
        return readback

    def _publication_receipt(
        self,
        value: object,
        *,
        final_name: str,
        encoded: bytes,
        require_no_replace_rename: bool = True,
    ) -> LifecycleV2ArtifactPublicationReceipt:
        if (
            type(value) is not LifecycleV2ArtifactPublicationReceipt
            or value.final_name != final_name
            or value.final_device != self._store_identity.directory_device
            or value.final_mode != 0o600
            or value.final_size != len(encoded)
            or value.file_fsync_completed is not True
            or value.directory_fsync_completed is not True
            or value.stable_readback_completed is not True
            or (value.existing_final_revalidated and value.no_replace_rename_completed)
            or (
                require_no_replace_rename
                and not value.existing_final_revalidated
                and value.no_replace_rename_completed is not True
            )
        ):
            raise LifecycleV2ArtifactPublicationUncertain(
                "artifact publication receipt is not exact"
            )
        return value

    def _require_wire_publication_binding(
        self,
        *,
        evidence: dict[str, object],
        envelope: UnverifiedLifecycleV2TransportEnvelope,
        file_name: str,
        file_device: int,
        file_inode: int,
        file_mode: int,
        file_size: int,
        live_receipt: LifecycleV2ArtifactPublicationReceipt | None,
    ) -> None:
        nested = evidence.get("wire_publication_receipt")
        if type(nested) is not dict:
            raise LifecycleV2RetentionUnconfirmed(
                "ordinal-two wire publication receipt is not one exact object"
            )
        kind = "result" if envelope.frame_type == "clean_stop_result" else "error"
        expected: dict[str, object] = {
            "artifact_directory_path": self._store_identity.artifact_directory_path,
            "artifact_directory_device": self._store_identity.directory_device,
            "artifact_directory_inode": self._store_identity.directory_inode,
            "artifact_path": f"{self._store_identity.artifact_directory_path}/{file_name}",
            "file_name": file_name,
            "file_device": file_device,
            "file_inode": file_inode,
            "file_mode": file_mode,
            "file_size": file_size,
            "artifact_kind": f"signed_{kind}_envelope",
            "signed_envelope_sha256": envelope.sha256,
            "frame_type": envelope.frame_type,
            "directory_fsync_completed": True,
            "stable_readback_completed": True,
        }
        if any(nested.get(name) != expected_value for name, expected_value in expected.items()):
            raise LifecycleV2RetentionUnconfirmed(
                "ordinal-two receipt crossed its physical file or directory identity"
            )
        if live_receipt is not None and (
            live_receipt.final_name != file_name
            or live_receipt.final_device != file_device
            or live_receipt.final_inode != file_inode
            or live_receipt.final_mode != file_mode
            or live_receipt.final_size != file_size
            or live_receipt.file_fsync_completed is not True
            or live_receipt.directory_fsync_completed is not True
            or (
                live_receipt.existing_final_revalidated and live_receipt.no_replace_rename_completed
            )
            or (
                not live_receipt.existing_final_revalidated
                and live_receipt.no_replace_rename_completed is not True
            )
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "live ordinal-two receipt does not prove exact publication"
            )

    def _load_namespace(self) -> None:
        try:
            initial_inventory = self._inventory()
            names = initial_inventory.names
            if any(name in _STAGING_NAMES - {_COMMIT_STAGING_NAME} for name in names):
                raise LifecycleV2RetentionUnconfirmed("staging artifact is retention ambiguity")
            unknown = tuple(name for name in names if _known_v2_name(name) is False)
            if unknown:
                raise LifecycleV2RetentionUnconfirmed("unknown lifecycle namespace entry")
            if LIFECYCLE_ROOT_FILE_NAME not in names:
                if names:
                    raise LifecycleV2RetentionUnconfirmed("orphan lifecycle-v2 artifact")
            else:
                root_encoded = self._read_artifact(LIFECYCLE_ROOT_FILE_NAME).encoded
                contract = _contract_version(root_encoded)
                if contract == _V1_ROOT_CONTRACT_VERSION:
                    raise LifecycleV2SlotConsumed("the shared root is already v1")
                if contract != LIFECYCLE_V2_ROOT_CONTRACT_VERSION:
                    raise LifecycleV2RetentionUnconfirmed("shared root version is unknown or mixed")
                self._root = decode_lifecycle_v2_root(root_encoded)
                self._opened_with_existing_root = True
                record_names = tuple(
                    name
                    for name in names
                    if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-record-")
                )
                records: list[LifecycleV2ProgressRecord] = []
                predecessor = self._root.sha256
                for name in record_names:
                    record = decode_lifecycle_v2_progress_record(self._read_artifact(name).encoded)
                    if (
                        name != lifecycle_v2_progress_file_name(record)
                        or record.ordinal != len(records) + 1
                        or record.root_sha256 != self._root.sha256
                        or record.graceful_stop_operation_id
                        != self._root.graceful_stop_operation_id
                        or record.predecessor_sha256 != predecessor
                        or record.deadline_boottime_ns != self._root.operation_deadline_boottime_ns
                    ):
                        raise LifecycleV2RetentionUnconfirmed("progress lineage is mixed or gapped")
                    if record.stage is LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED:
                        self._require_derived_request_intent(record)
                    self._require_stage_transition(record, records=tuple(records))
                    records.append(record)
                    predecessor = record.sha256
                self._records = tuple(records)
                self._load_wire(names)
                self._load_outcome(names)
                self._validate_transcripts(names)
            if self._inventory() != initial_inventory:
                raise LifecycleV2RetentionUnconfirmed(
                    "lifecycle namespace changed during complete stable load"
                )
        except (LifecycleV2SlotConsumed, LifecycleV2RetentionUnconfirmed):
            self._burn()
            raise
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "lifecycle namespace cannot be authenticated"
            ) from None

    def _load_wire(self, names: tuple[str, ...]) -> None:
        wire_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-")
        )
        if not wire_names:
            if len(self._records) >= 2 and self._records[1].stage in {
                LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            }:
                raise LifecycleV2RetentionUnconfirmed("ordinal two has no immutable wire artifact")
            return
        if len(wire_names) != 1 or len(self._records) < 2:
            raise LifecycleV2RetentionUnconfirmed("wire artifact is orphaned or conflicting")
        wire_readback = self._read_artifact(wire_names[0])
        envelope = decode_unverified_lifecycle_v2_transport_envelope(wire_readback.encoded)
        if wire_names[0] != lifecycle_v2_wire_file_name(envelope):
            raise LifecycleV2RetentionUnconfirmed("wire artifact name or digest disagrees")
        record = self._records[1]
        evidence = record.evidence.to_dict()
        prefix = (
            "clean_stop_result"
            if envelope.frame_type == "clean_stop_result"
            else "clean_stop_error"
        )
        if (
            record.stage.value != f"{prefix}_retained"
            or record.effect_kind != prefix
            or evidence[f"{prefix}_sha256"] != envelope.sha256
            or evidence[f"{prefix}_artifact_name"] != wire_names[0]
            or evidence["frame_type"] != envelope.frame_type
        ):
            raise LifecycleV2RetentionUnconfirmed("ordinal-two record and wire bytes disagree")
        self._require_wire_publication_binding(
            evidence=evidence,
            envelope=envelope,
            file_name=wire_names[0],
            file_device=wire_readback.file_device,
            file_inode=wire_readback.file_inode,
            file_mode=wire_readback.file_mode,
            file_size=wire_readback.file_size,
            live_receipt=None,
        )
        verifier = self._retained_wire_verifier
        if verifier is None:
            raise LifecycleV2RetentionUnconfirmed(
                "partial milestone-one cannot reauthenticate retained wire signatures "
                "without an injected verifier"
            )
        if self._root is None or not self._records:
            raise LifecycleV2RetentionUnconfirmed("retained wire has no exact dispatch prefix")
        request_intent = self._records[0]
        envelope_fields = envelope.to_dict()
        expected_dispatch_prefix = lifecycle_v2_dispatch_prefix_sha256(
            self._root,
            request_intent,
        )
        if (
            evidence["intent_sha256"] != request_intent.sha256
            or evidence["responder_identity_sha256"] != self._root.supervisor_process_epoch_sha256
            or evidence[f"{prefix}_artifact_path"]
            != f"{self._artifact_directory_path}/{wire_names[0]}"
            or evidence["envelope_contract_version"] != envelope_fields["contract_version"]
            or evidence["payload_contract_version"] != envelope_fields["payload_contract_version"]
            or evidence[f"{prefix}_payload_sha256"] != envelope_fields["payload_sha256"]
            or evidence[f"{prefix}_signature_sha256"] != envelope.signature_sha256
            or evidence["key_generation"] != envelope_fields["key_generation"]
            or evidence["signing_key_id"] != envelope_fields["signing_key_id"]
            or evidence["channel_id"] != envelope_fields["channel_id"]
            or evidence["lifecycle_dispatch_prefix_sha256"] != expected_dispatch_prefix
            or evidence["message_counter"] != envelope_fields["message_counter"]
            or evidence["deadline_boottime_ns"] != envelope_fields["deadline_boottime_ns"]
            or envelope_fields["environment"] != self._root.environment
            or envelope_fields["key_generation"] != self._root.transport_key_generation
            or envelope_fields["signing_key_id"] != self._root.supervisor_transport_key_id
            or envelope_fields["boot_epoch_sha256"] != self._root.boot_epoch_sha256
            or envelope_fields["host_process_epoch_sha256"] != self._root.host_process_epoch_sha256
            or envelope_fields["supervisor_process_epoch_sha256"]
            != self._root.supervisor_process_epoch_sha256
            or envelope_fields["channel_id"] != self._root.channel_id
            or envelope_fields["lifecycle_dispatch_prefix_sha256"] != expected_dispatch_prefix
            or envelope_fields["message_counter"] != 1
            or envelope_fields["deadline_boottime_ns"]
            != self._root.clean_stop_result_deadline_boottime_ns
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "retained wire does not bind the exact root, intent, record, and path"
            )
        try:
            sealed_result = verifier.reauthenticate_retained_terminal_wire(
                envelope=envelope,
                root=self._root,
                request_intent=request_intent,
                terminal_record=record,
                artifact_directory_path=self._artifact_directory_path,
            )
            verified = verifier.require_exact_authenticated_retained_terminal_wire(sealed_result)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "retained wire signature reauthentication failed"
            ) from None
        if (
            verified is not sealed_result
            or type(verified.envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or verified.envelope != envelope
            or verified.envelope.encoded != envelope.encoded
            or verified.authority_manifest_sha256 != self._root.transport_authority_manifest_sha256
            or verified.signer_role != "supervisor"
            or verified.root_sha256 != self._root.sha256
            or verified.request_intent_sha256 != request_intent.sha256
            or verified.terminal_record_sha256 != record.sha256
            or verified.artifact_directory_path != self._artifact_directory_path
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "retained wire verifier returned an invalid sealed authentication result"
            )
        self._wire = envelope

    def _load_outcome(self, names: tuple[str, ...]) -> None:
        outcome_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-outcome-")
        )
        if len(outcome_names) > 1:
            raise LifecycleV2RetentionUnconfirmed("multiple outcome candidates exist")
        if outcome_names:
            outcome = decode_lifecycle_v2_outcome(self._read_artifact(outcome_names[0]).encoded)
            if outcome_names[0] != outcome.file_name:
                raise LifecycleV2RetentionUnconfirmed("outcome name or digest disagrees")
            self._outcome = outcome
        loaded_commit: LifecycleV2OutcomeCommit | None = None
        commit_readback: LifecycleV2ArtifactReadback | None = None
        if LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME in names:
            if self._outcome is None:
                raise LifecycleV2RetentionUnconfirmed("commit has no outcome candidate")
            commit_readback = self._read_artifact(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME)
            loaded_commit = decode_lifecycle_v2_outcome_commit(
                commit_readback.encoded,
                outcome=self._outcome,
            )
        if _COMMIT_STAGING_NAME in names:
            if self._outcome is None:
                raise LifecycleV2RetentionUnconfirmed(
                    "fixed-marker staging has no outcome candidate"
                )
            self._commit_staging = decode_lifecycle_v2_outcome_commit(
                self._read_artifact(_COMMIT_STAGING_NAME).encoded,
                outcome=self._outcome,
            )
            if loaded_commit is not None and self._commit_staging != loaded_commit:
                raise LifecycleV2RetentionUnconfirmed(
                    "fixed-marker staging conflicts with the committed marker"
                )
        if loaded_commit is not None:
            if commit_readback is None:
                raise LifecycleV2RetentionUnconfirmed("fixed-marker readback is unavailable")
            publication = self._publication_receipt(
                self._store.finalize_preallocated_immutable(
                    staging_name=_COMMIT_STAGING_NAME,
                    final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                    encoded=loaded_commit.encoded,
                ),
                final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                encoded=loaded_commit.encoded,
            )
            if (
                publication.existing_final_revalidated is not True
                or publication.no_replace_rename_completed
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "retained fixed marker was not durably revalidated"
                )
            revalidated = self._read_artifact(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME)
            if (
                revalidated != commit_readback
                or revalidated.encoded != loaded_commit.encoded
                or revalidated.file_device != publication.final_device
                or revalidated.file_inode != publication.final_inode
                or revalidated.file_mode != publication.final_mode
                or revalidated.file_size != publication.final_size
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "durably revalidated fixed marker changed during repository load"
                )
            self._commit = loaded_commit

    def _validate_transcripts(self, names: tuple[str, ...]) -> None:
        transcript_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-transcript-")
        )
        retained_transcripts: dict[str, LifecycleV2Transcript] = {}
        for name in transcript_names:
            transcript = decode_lifecycle_v2_transcript(self._read_artifact(name).encoded)
            if name != transcript.file_name:
                raise LifecycleV2RetentionUnconfirmed("transcript name or digest disagrees")
            expected = self._transcript(last_ordinal=transcript.entries[-1].ordinal)
            if transcript != expected:
                raise LifecycleV2RetentionUnconfirmed("transcript is not an exact stable prefix")
            retained_transcripts[transcript.sha256] = transcript
        for record in self._records:
            if record.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
                classified_transcript = self._transcript(last_ordinal=record.ordinal - 1)
                if (
                    record.evidence.to_dict()["classified_transcript_sha256"]
                    != classified_transcript.sha256
                    or retained_transcripts.get(classified_transcript.sha256)
                    != classified_transcript
                ):
                    raise LifecycleV2RetentionUnconfirmed(
                        "recovery intent does not bind its exact predecessor prefix"
                    )
        if self._outcome is not None:
            self._validate_loaded_outcome(retained_transcripts)

    def _validate_loaded_outcome(
        self,
        retained_transcripts: dict[str, LifecycleV2Transcript],
    ) -> None:
        if self._root is None or self._outcome is None:
            raise LifecycleV2RetentionUnconfirmed("terminal artifacts have no lifecycle root")
        if not self._records:
            raise LifecycleV2RetentionUnconfirmed(
                "terminal artifacts cannot classify a root-only namespace"
            )
        full_transcript = self._transcript()
        retained_full_transcript = retained_transcripts.get(full_transcript.sha256)
        if retained_full_transcript != full_transcript:
            raise LifecycleV2RetentionUnconfirmed(
                "outcome does not bind the exact complete retained prefix"
            )
        last_record = self._records[-1]
        outcome_fields = self._outcome.to_dict()
        if (
            outcome_fields["graceful_stop_operation_id"] != self._root.graceful_stop_operation_id
            or outcome_fields["root_sha256"] != self._root.sha256
            or outcome_fields["ordinal"] != len(self._records) + 1
            or outcome_fields["predecessor_sha256"] != last_record.sha256
            or outcome_fields["final_stage"] != last_record.stage.value
            or outcome_fields["transcript_sha256"] != full_transcript.sha256
            or outcome_fields["admission_started_boottime_ns"]
            != self._root.admission_started_boottime_ns
            or outcome_fields["operation_deadline_boottime_ns"]
            != self._root.operation_deadline_boottime_ns
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "outcome does not bind the loaded root and complete retained prefix"
            )
        if self._outcome.status == "recovery_required":
            if (
                last_record.stage is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
                or outcome_fields["reason_code"] != last_record.evidence.to_dict()["reason_code"]
            ):
                raise LifecycleV2RetentionUnconfirmed(
                    "recovery outcome has no exact classification intent"
                )
        elif (
            len(self._records) != 22
            or last_record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "confirmed success has no complete terminal-cleanup prefix"
            )
        if self._commit is not None:
            commit_fields = self._commit.to_dict()
            if (
                commit_fields["graceful_stop_operation_id"] != self._root.graceful_stop_operation_id
                or commit_fields["root_sha256"] != self._root.sha256
                or commit_fields["outcome_sha256"] != self._outcome.sha256
                or commit_fields["outcome_status"] != self._outcome.status
                or commit_fields["transcript_sha256"] != full_transcript.sha256
                or commit_fields["admission_started_boottime_ns"]
                != self._root.admission_started_boottime_ns
                or commit_fields["operation_deadline_boottime_ns"]
                != self._root.operation_deadline_boottime_ns
            ):
                raise LifecycleV2RetentionUnconfirmed(
                    "commit marker does not bind the loaded terminal lineage"
                )
        if self._commit_staging is not None:
            staging_fields = self._commit_staging.to_dict()
            if (
                staging_fields["graceful_stop_operation_id"]
                != self._root.graceful_stop_operation_id
                or staging_fields["root_sha256"] != self._root.sha256
                or staging_fields["outcome_sha256"] != self._outcome.sha256
                or staging_fields["outcome_status"] != self._outcome.status
                or staging_fields["transcript_sha256"] != full_transcript.sha256
                or staging_fields["admission_started_boottime_ns"]
                != self._root.admission_started_boottime_ns
                or staging_fields["operation_deadline_boottime_ns"]
                != self._root.operation_deadline_boottime_ns
            ):
                raise LifecycleV2RetentionUnconfirmed(
                    "fixed-marker staging does not bind the loaded terminal lineage"
                )

    def _require_stage_transition(
        self,
        record: LifecycleV2ProgressRecord,
        *,
        records: tuple[LifecycleV2ProgressRecord, ...] | None = None,
    ) -> None:
        exact_records = self._records if records is None else records
        if record.ordinal != len(exact_records) + 1:
            raise LifecycleV2RepositoryRejected("progress ordinal is not next")
        if records is None and (self._outcome is not None or self._commit is not None):
            raise LifecycleV2RepositoryRejected("terminal outcome already retained")
        if record.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
            if not exact_records:
                raise LifecycleV2RepositoryRejected(
                    "recovery classification requires the ordinal-one request prefix"
                )
            if any(
                item.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
                for item in exact_records
            ):
                raise LifecycleV2RepositoryRejected(
                    "recovery classification intent is already retained"
                )
            return
        if any(
            item.stage
            in {
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
                LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
            }
            for item in exact_records
        ):
            raise LifecycleV2RepositoryRejected("normal continuation after failure is forbidden")
        expected = NORMAL_STAGE_BY_ORDINAL.get(record.ordinal)
        if record.ordinal == 2 and record.stage is LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED:
            return
        if record.stage is not expected:
            raise LifecycleV2RepositoryRejected("normal lifecycle stage is out of order")

    def _require_record_binding(self, record: LifecycleV2ProgressRecord) -> None:
        if type(record) is not LifecycleV2ProgressRecord or self._root is None:
            raise LifecycleV2RepositoryRejected("lifecycle root is not reserved")
        try:
            verified_record = decode_lifecycle_v2_progress_record(record.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected(
                "progress record is not canonically valid"
            ) from None
        if verified_record != record:
            raise LifecycleV2RepositoryRejected(
                "progress record changed under canonical validation"
            )
        predecessor = self._records[-1].sha256 if self._records else self._root.sha256
        if (
            record.root_sha256 != self._root.sha256
            or record.graceful_stop_operation_id != self._root.graceful_stop_operation_id
            or record.predecessor_sha256 != predecessor
            or record.deadline_boottime_ns != self._root.operation_deadline_boottime_ns
        ):
            raise LifecycleV2RepositoryRejected("progress record does not bind this lifecycle")
        self._require_stage_transition(record)

    def _require_derived_request_intent(
        self,
        record: LifecycleV2ProgressRecord,
        *,
        basis: LifecycleV2CleanStopRequestBasis | None = None,
    ) -> None:
        if self._root is None:
            raise LifecycleV2RepositoryRejected("request intent requires a lifecycle root")
        try:
            derived_basis = LifecycleV2CleanStopRequestBasis.from_root(self._root)
            if basis is not None:
                if type(basis) is not LifecycleV2CleanStopRequestBasis:
                    raise TrustedTimeGracefulStopV2Rejected("request basis type is invalid")
                decoded_basis = decode_lifecycle_v2_clean_stop_request_basis(basis.encoded)
                if decoded_basis != basis or decoded_basis != derived_basis:
                    raise TrustedTimeGracefulStopV2Rejected("request basis is not root-derived")
            expected_evidence = {
                "target_identity_sha256": self._root.supervisor_container_id,
                "arguments_sha256": derived_basis.sha256,
                "admission_sha256": self._root.admission_sha256,
                "channel_id": self._root.channel_id,
                "call_deadline_boottime_ns": (self._root.clean_stop_result_deadline_boottime_ns),
                "admission_started_boottime_ns": self._root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": self._root.operation_deadline_boottime_ns,
            }
            if (
                record.ordinal != 1
                or record.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
                or record.effect_kind != "clean_stop_request"
                or record.evidence.to_dict() != expected_evidence
            ):
                raise TrustedTimeGracefulStopV2Rejected(
                    "request intent is not exactly root/basis-derived"
                )
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected(
                "request intent is not exactly root/basis-derived"
            ) from None

    @property
    def status(self) -> LifecycleV2RepositoryStatus:
        self._require_origin()
        if self._closed:
            raise LifecycleV2RetentionUnconfirmed("repository is closed")
        self._require_store_binding()
        if self._poisoned:
            return LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED
        if self._commit is not None:
            return LifecycleV2RepositoryStatus.OUTCOME_COMMITTED
        if self._outcome is not None:
            return LifecycleV2RepositoryStatus.OUTCOME_COMMIT_UNCONFIRMED
        if self._root is None:
            return LifecycleV2RepositoryStatus.UNRESERVED
        if self._records and self._records[-1].stage in {
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        }:
            return LifecycleV2RepositoryStatus.RECOVERY_REQUIRED
        return LifecycleV2RepositoryStatus.ROOT_RESERVED

    def reserve_root(self, root: LifecycleV2Root) -> None:
        self._require_owner()
        if type(root) is not LifecycleV2Root:
            raise LifecycleV2RepositoryRejected("root must be an exact lifecycle-v2 value")
        try:
            verified_root = decode_lifecycle_v2_root(root.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected("root is not canonically valid") from None
        if verified_root != root:
            raise LifecycleV2RepositoryRejected("root changed under canonical validation")
        root = verified_root
        if self._root is not None:
            raise LifecycleV2SlotConsumed("the shared lifecycle slot is consumed")
        try:
            if self._inventory().names:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "artifact namespace changed before root reservation"
                )
            receipt = self._publication_receipt(
                self._store.create_root_exclusive(LIFECYCLE_ROOT_FILE_NAME, root.encoded),
                final_name=LIFECYCLE_ROOT_FILE_NAME,
                encoded=root.encoded,
                require_no_replace_rename=False,
            )
            if receipt.existing_final_revalidated or receipt.no_replace_rename_completed:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "exclusive root creation revalidated an existing artifact"
                )
            if self._read_artifact(LIFECYCLE_ROOT_FILE_NAME).encoded != root.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("root creation may have begun") from None
        self._root = root

    def retain_request_intent(
        self,
        record: LifecycleV2ProgressRecord,
        basis: LifecycleV2CleanStopRequestBasis,
    ) -> None:
        _retain_lifecycle_v2_request_intent(self, record, basis)

    def retain_authenticated_terminal_wire(
        self,
        record: LifecycleV2ProgressRecord,
        authenticated_envelope: _FakeAuthenticatedLifecycleV2TransportEnvelope,
    ) -> None:
        _retain_lifecycle_v2_authenticated_terminal_wire(
            self,
            record,
            authenticated_envelope,
        )

    def retain_transport_cleanup_commitment(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_transport_cleanup_commitment(self, record)

    def retain_transport_quiescence(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_transport_quiescence(self, record)

    def retain_reauthentication_intent(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_reauthentication_intent(self, record)

    def retain_reauthentication_result(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_reauthentication_result(self, record)

    def retain_effect_intent(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_effect_intent(self, record)

    def retain_effect_result(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_effect_result(self, record)

    def retain_terminal_cleanup_intent(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_terminal_cleanup_intent(self, record)

    def retain_terminal_cleanup_result(self, record: LifecycleV2ProgressRecord) -> None:
        _retain_lifecycle_v2_terminal_cleanup_result(self, record)

    def retain_recovery_classification_intent(
        self,
        authenticated_intent: LifecycleV2AuthenticatedRecoveryIntent,
    ) -> LifecycleV2ProgressRecord:
        self._require_owner()
        try:
            exact_intent = require_authenticated_lifecycle_v2_recovery_intent(authenticated_intent)
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2RepositoryRejected(
                "recovery classification intent is not authenticated"
            ) from error
        record = exact_intent.record
        if record.stage is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("recovery-classification stage is wrong")
        self._require_record_binding(record)
        classified_transcript = self._transcript()
        if (
            self._root is None
            or exact_intent.root_sha256 != self._root.sha256
            or exact_intent.classified_transcript_sha256 != classified_transcript.sha256
            or record.evidence.to_dict()["classified_transcript_sha256"]
            != classified_transcript.sha256
        ):
            raise LifecycleV2RepositoryRejected(
                "recovery intent does not bind the classified prefix"
            )
        try:
            if (
                self._read_artifact(classified_transcript.file_name).encoded
                != classified_transcript.encoded
            ):
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "classified transcript retention is unconfirmed"
            ) from None
        try:
            consumed_intent = consume_authenticated_lifecycle_v2_recovery_intent(
                authenticated_intent
            )
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2RepositoryRejected(
                "recovery classification intent is invalid or already consumed"
            ) from error
        if consumed_intent is not exact_intent or consumed_intent.record != record:
            raise LifecycleV2RepositoryRejected(
                "recovery classification intent changed before retention"
            )
        try:
            record_name = lifecycle_v2_progress_file_name(consumed_intent.record)
            self._publication_receipt(
                self._store.publish_immutable(
                    staging_name=_RECORD_STAGING_NAME,
                    final_name=record_name,
                    encoded=consumed_intent.record.encoded,
                ),
                final_name=record_name,
                encoded=consumed_intent.record.encoded,
            )
            if self._read_artifact(record_name).encoded != consumed_intent.record.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("progress retention may have begun") from None
        self._records = (*self._records, consumed_intent.record)
        return consumed_intent.record

    def _transcript(self, *, last_ordinal: int | None = None) -> LifecycleV2Transcript:
        if self._root is None:
            raise LifecycleV2RepositoryRejected("transcript requires a lifecycle root")
        selected = self._records if last_ordinal is None else self._records[:last_ordinal]
        if last_ordinal is not None and (last_ordinal < 0 or len(selected) != last_ordinal):
            raise LifecycleV2RetentionUnconfirmed("transcript references an absent prefix")
        entries = [
            LifecycleV2TranscriptEntry(
                ordinal=0,
                stage=LifecycleV2Stage.ROOT_RESERVED,
                record_artifact_kind="root",
                record_contract_version=LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
                record_artifact_sha256=self._root.sha256,
                predecessor_sha256=None,
            )
        ]
        for record in selected:
            wire_kind: str | None = None
            wire_path: str | None = None
            wire_name: str | None = None
            wire_sha256: str | None = None
            if record.stage in {
                LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            }:
                evidence = record.evidence.to_dict()
                prefix = (
                    "clean_stop_result"
                    if record.stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
                    else "clean_stop_error"
                )
                wire_kind = (
                    "signed_result_envelope"
                    if prefix == "clean_stop_result"
                    else "signed_error_envelope"
                )
                wire_path = cast(str, evidence[f"{prefix}_artifact_path"])
                wire_name = cast(str, evidence[f"{prefix}_artifact_name"])
                wire_sha256 = cast(str, evidence[f"{prefix}_sha256"])
            entries.append(
                LifecycleV2TranscriptEntry(
                    ordinal=record.ordinal,
                    stage=record.stage,
                    record_artifact_kind="progress",
                    record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                    record_artifact_sha256=record.sha256,
                    predecessor_sha256=record.predecessor_sha256,
                    wire_artifact_kind=wire_kind,
                    wire_artifact_path=wire_path,
                    wire_artifact_file_name=wire_name,
                    wire_artifact_sha256=wire_sha256,
                )
            )
        return LifecycleV2Transcript(
            environment=self._root.environment,
            graceful_stop_operation_id=self._root.graceful_stop_operation_id,
            root_sha256=self._root.sha256,
            entries=tuple(entries),
        )

    def publish_transcript(self) -> LifecycleV2Transcript:
        self._require_owner()
        if self._outcome is not None or self._commit is not None:
            raise LifecycleV2RepositoryRejected("terminal outcome already retained")
        transcript = self._transcript()
        try:
            self._publication_receipt(
                self._store.publish_immutable(
                    staging_name=_TRANSCRIPT_STAGING_NAME,
                    final_name=transcript.file_name,
                    encoded=transcript.encoded,
                ),
                final_name=transcript.file_name,
                encoded=transcript.encoded,
            )
            if self._read_artifact(transcript.file_name).encoded != transcript.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("transcript publication may have begun") from None
        return transcript

    @staticmethod
    def _sample_boottime(clock: LifecycleV2BoottimeClock) -> int:
        try:
            sample = clock.sample_boottime_ns()
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RepositoryRejected("CLOCK_BOOTTIME sample is unavailable") from None
        if type(sample) is not int or not 0 <= sample <= MAXIMUM_SIGNED_INTEGER:
            raise LifecycleV2RepositoryRejected("CLOCK_BOOTTIME sample is outside its exact bounds")
        return sample

    def _require_published_final_transcript(self) -> LifecycleV2Transcript:
        transcript = self._transcript()
        try:
            readback = self._read_artifact(transcript.file_name)
            if readback.encoded != transcript.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RepositoryRejected(
                "exact final transcript is not stably published"
            ) from None
        return transcript

    def _publish_outcome_candidate(self, outcome: LifecycleV2Outcome) -> None:
        if self._outcome is not None:
            if self._outcome != outcome:
                raise LifecycleV2RepositoryRejected(
                    "a different outcome candidate is already retained"
                )
            return
        try:
            receipt = self._publication_receipt(
                self._store.publish_immutable(
                    staging_name=_OUTCOME_STAGING_NAME,
                    final_name=outcome.file_name,
                    encoded=outcome.encoded,
                ),
                final_name=outcome.file_name,
                encoded=outcome.encoded,
            )
            readback = self._read_artifact(outcome.file_name)
            if (
                readback.encoded != outcome.encoded
                or readback.file_device != receipt.final_device
                or readback.file_inode != receipt.final_inode
                or readback.file_mode != receipt.final_mode
                or readback.file_size != receipt.final_size
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "outcome candidate stable readback disagrees"
                )
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "outcome candidate publication may have begun"
            ) from None
        self._outcome = outcome

    def _publish_fixed_marker(
        self,
        *,
        outcome: LifecycleV2Outcome,
        encoded: bytes,
        finalize_staging: bool,
    ) -> LifecycleV2OutcomeCommit:
        try:
            if finalize_staging:
                publication = self._store.finalize_preallocated_immutable(
                    staging_name=_COMMIT_STAGING_NAME,
                    final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                    encoded=encoded,
                )
            else:
                publication = self._store.publish_immutable(
                    staging_name=_COMMIT_STAGING_NAME,
                    final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                    encoded=encoded,
                )
            self._publication_receipt(
                publication,
                final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                encoded=encoded,
            )
            if self._read_artifact(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME).encoded != encoded:
                raise LifecycleV2ArtifactPublicationUncertain(
                    "fixed marker stable readback disagrees"
                )
            commit = decode_lifecycle_v2_outcome_commit(encoded, outcome=outcome)
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "fixed-marker publication may have begun"
            ) from None
        self._commit = commit
        return commit

    def commit_recovery_outcome(
        self,
        *,
        clock: LifecycleV2BoottimeClock,
        created_at_utc: str,
    ) -> tuple[LifecycleV2Outcome, LifecycleV2OutcomeCommit]:
        """Derive and commit only the deterministic classified recovery outcome."""

        self._require_owner()
        if self._commit is not None:
            raise LifecycleV2RepositoryRejected("terminal outcome already committed")
        if self._outcome is not None:
            raise LifecycleV2RepositoryRejected(
                "an outcome candidate already exists; use exact-candidate finalization"
            )
        if (
            self._root is None
            or not self._records
            or self._records[-1].stage
            is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
        ):
            raise LifecycleV2RepositoryRejected(
                "recovery outcome requires a retained classification intent"
            )
        transcript = self._require_published_final_transcript()
        authorized = self._sample_boottime(clock)
        if authorized > MAXIMUM_SIGNED_INTEGER - LIFECYCLE_V2_COMMIT_BUDGET_NS:
            raise LifecycleV2RepositoryRejected("recovery commit deadline overflows")
        recovery_record = self._records[-1]
        recovery_evidence = recovery_record.evidence.to_dict()
        outcome = LifecycleV2Outcome.capture(
            {
                "contract_version": LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
                "service": LIFECYCLE_V2_SERVICE,
                "status": "recovery_required",
                "lifecycle_version": 2,
                "graceful_stop_operation_id": self._root.graceful_stop_operation_id,
                "root_sha256": self._root.sha256,
                "ordinal": recovery_record.ordinal + 1,
                "predecessor_sha256": recovery_record.sha256,
                "final_stage": recovery_record.stage.value,
                "transcript_sha256": transcript.sha256,
                "reason_code": recovery_evidence["reason_code"],
                "pre_effect_binding_sha256": None,
                "post_teardown_binding_sha256": None,
                "volume_proof_sha256": None,
                "terminal_cleanup_sha256": None,
                "stop_effects_confirmed": False,
                "teardown_confirmed": False,
                "terminal_cleanup_confirmed": False,
                "admission_started_boottime_ns": (self._root.admission_started_boottime_ns),
                "operation_deadline_boottime_ns": (self._root.operation_deadline_boottime_ns),
                "commit_protocol_started_boottime_ns": authorized,
                "commit_publication_authorization_deadline_boottime_ns": (
                    authorized + LIFECYCLE_V2_COMMIT_BUDGET_NS
                ),
                "commit_authorized_boottime_ns": authorized,
                "created_at_utc": created_at_utc,
            }
        )
        marker_basis = _LifecycleV2OutcomeCommitMarkerBasis.prepare(outcome)
        marker_encoded = marker_basis.materialize(authorized)
        self._publish_outcome_candidate(outcome)
        commit = self._publish_fixed_marker(
            outcome=outcome,
            encoded=marker_encoded,
            finalize_staging=False,
        )
        return outcome, commit

    def commit_confirmed_success(
        self,
        *,
        lineage: LifecycleV2NormalProgressLineage,
        clock: LifecycleV2BoottimeClock,
        precommit_disposer: LifecycleV2SuccessPrecommitDisposer,
        created_at_utc: str,
    ) -> tuple[LifecycleV2Outcome, LifecycleV2OutcomeCommit]:
        """Publish success only after exact ordinal 22 and the final authorization."""

        self._require_owner()
        if self._commit is not None:
            raise LifecycleV2RepositoryRejected("terminal outcome already committed")
        if self._outcome is not None:
            raise LifecycleV2RepositoryRejected(
                "an outcome candidate already exists; alternate success is forbidden"
            )
        if (
            self._root is None
            or self._opened_with_existing_root
        ):
            raise LifecycleV2RepositoryRejected(
                "confirmed success requires one live newly reserved root"
            )
        try:
            snapshot = consume_exact_lifecycle_v2_confirmed_success_lineage(lineage)
        except (AttributeError, TypeError, TrustedTimeLifecycleV2SemanticsRejected) as error:
            raise LifecycleV2RepositoryRejected(
                "confirmed success requires one sealed exact ordinal-22 lineage"
            ) from error
        if (
            type(snapshot) is not LifecycleV2ConfirmedSuccessLineageSnapshot
            or snapshot.root != self._root
            or snapshot.root_encoded != self._root.encoded
            or snapshot.lineage_provenance != "authenticated_injected_lineage"
            or len(self._records) != 22
            or len(snapshot.records) != 21
            or snapshot.records != self._records[1:]
            or any(
                sealed_record is not retained_record
                for sealed_record, retained_record in zip(
                    snapshot.records,
                    self._records[1:],
                    strict=True,
                )
            )
            or snapshot.record_encoded
            != tuple(record.encoded for record in self._records[1:])
            or self._records[0].ordinal != 1
            or self._records[0].stage
            is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
            or snapshot.records[0].predecessor_sha256 != self._records[0].sha256
            or snapshot.records[-1].stage
            is not LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED
        ):
            raise LifecycleV2RepositoryRejected(
                "confirmed-success lineage and retained repository prefix disagree"
            )
        transcript = self._require_published_final_transcript()
        protocol_start = self._sample_boottime(clock)
        if (
            protocol_start > MAXIMUM_SIGNED_INTEGER - LIFECYCLE_V2_COMMIT_BUDGET_NS
            or protocol_start >= self._root.operation_deadline_boottime_ns
        ):
            raise LifecycleV2RepositoryRejected(
                "confirmed-success protocol entry reached its authorization cutoff"
            )
        pre_effect = snapshot.records[4]
        post_teardown = snapshot.records[18]
        volume_proof = snapshot.records[16]
        terminal_cleanup = snapshot.records[20]
        outcome = LifecycleV2Outcome.capture(
            {
                "contract_version": LIFECYCLE_V2_OUTCOME_CONTRACT_VERSION,
                "service": LIFECYCLE_V2_SERVICE,
                "status": "confirmed_success",
                "lifecycle_version": 2,
                "graceful_stop_operation_id": self._root.graceful_stop_operation_id,
                "root_sha256": self._root.sha256,
                "ordinal": 23,
                "predecessor_sha256": terminal_cleanup.sha256,
                "final_stage": terminal_cleanup.stage.value,
                "transcript_sha256": transcript.sha256,
                "reason_code": "completed",
                "pre_effect_binding_sha256": pre_effect.evidence.to_dict()[
                    "binding_semantic_sha256"
                ],
                "post_teardown_binding_sha256": post_teardown.evidence.to_dict()[
                    "binding_semantic_sha256"
                ],
                "volume_proof_sha256": volume_proof.sha256,
                "terminal_cleanup_sha256": terminal_cleanup.sha256,
                "stop_effects_confirmed": True,
                "teardown_confirmed": True,
                "terminal_cleanup_confirmed": True,
                "admission_started_boottime_ns": (self._root.admission_started_boottime_ns),
                "operation_deadline_boottime_ns": (self._root.operation_deadline_boottime_ns),
                "commit_protocol_started_boottime_ns": protocol_start,
                "commit_publication_authorization_deadline_boottime_ns": min(
                    protocol_start + LIFECYCLE_V2_COMMIT_BUDGET_NS,
                    self._root.operation_deadline_boottime_ns,
                ),
                "commit_authorized_boottime_ns": None,
                "created_at_utc": created_at_utc,
            }
        )
        try:
            if (
                consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository(snapshot)
                is not snapshot
            ):
                raise TrustedTimeLifecycleV2SemanticsRejected(
                    "confirmed-success repository snapshot identity changed"
                )
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "confirmed-success repository authorization was not consumed"
            ) from None
        self._publish_outcome_candidate(outcome)
        try:
            marker_basis = _LifecycleV2OutcomeCommitMarkerBasis.prepare(outcome)
            sealed_disposition = precommit_disposer.dispose_and_prove_empty(
                root=self._root,
                transcript=transcript,
                outcome=outcome,
                artifact_store_identity=self._store_identity,
            )
            disposition = precommit_disposer.require_exact_disposed_and_empty(sealed_disposition)
            if (
                disposition is not sealed_disposition
                or disposition.root_sha256 != self._root.sha256
                or disposition.transcript_sha256 != transcript.sha256
                or disposition.outcome_sha256 != outcome.sha256
                or disposition.candidate_handle_disposed is not True
                or disposition.transcript_handle_disposed is not True
                or type(disposition.transient_descriptor_count) is not int
                or disposition.transient_descriptor_count != 0
                or type(disposition.registry_entry_count) is not int
                or disposition.registry_entry_count != 0
            ):
                raise LifecycleV2ArtifactPublicationUncertain(
                    "success precommit descriptor or registry projection is not empty"
                )
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            if isinstance(error, LifecycleV2ArtifactPublicationUncertain):
                message = str(error)
            else:
                message = "success precommit owner disposal is unconfirmed"
            raise LifecycleV2RetentionUnconfirmed(message) from None

        authorization_deadline = cast(
            int,
            outcome.to_dict()["commit_publication_authorization_deadline_boottime_ns"],
        )
        # This is the final classifying read and check.  The next operation is
        # mechanical marker materialization followed directly by publication.
        try:
            authorized = self._sample_boottime(clock)
        except LifecycleV2RepositoryRejected:
            self._burn()
            raise LifecycleV2RetentionUnconfirmed(
                "confirmed-success final CLOCK_BOOTTIME sample is unconfirmed"
            ) from None
        if not (
            protocol_start <= authorized < authorization_deadline
            and authorized < self._root.operation_deadline_boottime_ns
        ):
            self._burn()
            raise LifecycleV2RetentionUnconfirmed(
                "confirmed-success final authorization is equality-expired"
            )
        marker_encoded = marker_basis.materialize(authorized)
        commit = self._publish_fixed_marker(
            outcome=outcome,
            encoded=marker_encoded,
            finalize_staging=False,
        )
        return outcome, commit

    def finalize_retained_outcome_commit(self) -> LifecycleV2OutcomeCommit:
        """Finalize only the exact retained candidate/marker preimage after restart."""

        self._require_owner()
        if self._commit is not None:
            return self._commit
        if self._outcome is None:
            raise LifecycleV2RepositoryRejected(
                "outcome finalization requires one exact retained candidate"
            )
        basis = _LifecycleV2OutcomeCommitMarkerBasis.prepare(self._outcome)
        if self._outcome.status == "confirmed_success":
            if self._commit_staging is None:
                raise LifecycleV2RepositoryRejected(
                    "confirmed-success candidate lacks an authenticated marker preimage"
                )
            authorized = cast(
                int,
                self._commit_staging.to_dict()["commit_authorized_boottime_ns"],
            )
            encoded = basis.materialize(authorized)
            if encoded != self._commit_staging.encoded:
                raise LifecycleV2RetentionUnconfirmed("confirmed-success marker preimage changed")
            return self._publish_fixed_marker(
                outcome=self._outcome,
                encoded=encoded,
                finalize_staging=True,
            )
        authorized = cast(
            int,
            self._outcome.to_dict()["commit_authorized_boottime_ns"],
        )
        encoded = basis.materialize(authorized)
        if self._commit_staging is not None:
            if encoded != self._commit_staging.encoded:
                raise LifecycleV2RetentionUnconfirmed("recovery marker preimage changed")
            finalize_staging = True
        else:
            finalize_staging = False
        return self._publish_fixed_marker(
            outcome=self._outcome,
            encoded=encoded,
            finalize_staging=finalize_staging,
        )


def _build_named_lifecycle_v2_retention_endpoints() -> tuple[Callable[..., None], ...]:
    """Keep the shared append primitive unreachable behind exact named stages."""

    def retain_record(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
        *,
        envelope: UnverifiedLifecycleV2TransportEnvelope | None = None,
    ) -> None:
        repository._require_owner()
        repository._require_record_binding(record)
        try:
            if envelope is not None:
                wire_name = lifecycle_v2_wire_file_name(envelope)
                wire_receipt = repository._publication_receipt(
                    repository._store.publish_immutable(
                        staging_name=(
                            _WIRE_RESULT_STAGING_NAME
                            if envelope.frame_type == "clean_stop_result"
                            else _WIRE_ERROR_STAGING_NAME
                        ),
                        final_name=wire_name,
                        encoded=envelope.encoded,
                    ),
                    final_name=wire_name,
                    encoded=envelope.encoded,
                )
                wire_readback = repository._read_artifact(wire_name)
                if (
                    wire_readback.encoded != envelope.encoded
                    or wire_readback.file_device != wire_receipt.final_device
                    or wire_readback.file_inode != wire_receipt.final_inode
                    or wire_readback.file_mode != wire_receipt.final_mode
                    or wire_readback.file_size != wire_receipt.final_size
                ):
                    raise LifecycleV2ArtifactPublicationUncertain(
                        "wire publication receipt and retained-file readback disagree"
                    )
                repository._require_wire_publication_binding(
                    evidence=record.evidence.to_dict(),
                    envelope=envelope,
                    file_name=wire_name,
                    file_device=wire_readback.file_device,
                    file_inode=wire_readback.file_inode,
                    file_mode=wire_readback.file_mode,
                    file_size=wire_readback.file_size,
                    live_receipt=wire_receipt,
                )
            record_name = lifecycle_v2_progress_file_name(record)
            repository._publication_receipt(
                repository._store.publish_immutable(
                    staging_name=_RECORD_STAGING_NAME,
                    final_name=record_name,
                    encoded=record.encoded,
                ),
                final_name=record_name,
                encoded=record.encoded,
            )
            if repository._read_artifact(record_name).encoded != record.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            repository._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("progress retention may have begun") from None
        repository._records = (*repository._records, record)
        if envelope is not None:
            repository._wire = envelope

    def retain_request_intent(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
        basis: LifecycleV2CleanStopRequestBasis,
    ) -> None:
        repository._require_owner()
        if record.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("request-intent method received another stage")
        repository._require_derived_request_intent(record, basis=basis)
        retain_record(repository, record)

    def retain_authenticated_terminal_wire(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
        authenticated_envelope: _FakeAuthenticatedLifecycleV2TransportEnvelope,
    ) -> None:
        repository._require_owner()
        if record.stage not in {
            LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("terminal-wire method received another stage")
        try:
            envelope = _require_fake_authenticated_lifecycle_v2_transport_envelope(
                authenticated_envelope
            )
        except TrustedTimeGracefulStopV2Rejected as error:
            raise LifecycleV2RepositoryRejected(
                "ordinal two requires fake-authenticated signed wire bytes"
            ) from error
        expected_frame = (
            "clean_stop_result"
            if record.stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            else "clean_stop_error"
        )
        evidence = record.evidence.to_dict()
        if (
            envelope.frame_type != expected_frame
            or evidence[f"{expected_frame}_sha256"] != envelope.sha256
            or evidence[f"{expected_frame}_artifact_name"]
            != lifecycle_v2_wire_file_name(envelope)
        ):
            raise LifecycleV2RepositoryRejected("wire envelope and ordinal two disagree")
        retain_record(repository, record, envelope=envelope)

    def retain_transport_cleanup_commitment(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage is not LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED:
            raise LifecycleV2RepositoryRejected("cleanup-commitment stage is wrong")
        retain_record(repository, record)

    def retain_transport_quiescence(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage is not LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED:
            raise LifecycleV2RepositoryRejected("transport-quiescence stage is wrong")
        retain_record(repository, record)

    def retain_reauthentication_intent(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage not in {
            LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
            LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("reauthentication-intent stage is wrong")
        retain_record(repository, record)

    def retain_reauthentication_result(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage not in {
            LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
            LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
        }:
            raise LifecycleV2RepositoryRejected("reauthentication-result stage is wrong")
        retain_record(repository, record)

    def retain_effect_intent(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage not in {
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("effect-intent stage is wrong")
        retain_record(repository, record)

    def retain_effect_result(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage not in {
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
        }:
            raise LifecycleV2RepositoryRejected("effect-result stage is wrong")
        retain_record(repository, record)

    def retain_terminal_cleanup_intent(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("terminal-cleanup intent stage is wrong")
        retain_record(repository, record)

    def retain_terminal_cleanup_result(
        repository: _LifecycleV2Repository,
        record: LifecycleV2ProgressRecord,
    ) -> None:
        repository._require_owner()
        if record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED:
            raise LifecycleV2RepositoryRejected("terminal-cleanup result stage is wrong")
        retain_record(repository, record)

    return (
        retain_request_intent,
        retain_authenticated_terminal_wire,
        retain_transport_cleanup_commitment,
        retain_transport_quiescence,
        retain_reauthentication_intent,
        retain_reauthentication_result,
        retain_effect_intent,
        retain_effect_result,
        retain_terminal_cleanup_intent,
        retain_terminal_cleanup_result,
    )


(
    _retain_lifecycle_v2_request_intent,
    _retain_lifecycle_v2_authenticated_terminal_wire,
    _retain_lifecycle_v2_transport_cleanup_commitment,
    _retain_lifecycle_v2_transport_quiescence,
    _retain_lifecycle_v2_reauthentication_intent,
    _retain_lifecycle_v2_reauthentication_result,
    _retain_lifecycle_v2_effect_intent,
    _retain_lifecycle_v2_effect_result,
    _retain_lifecycle_v2_terminal_cleanup_intent,
    _retain_lifecycle_v2_terminal_cleanup_result,
) = _build_named_lifecycle_v2_retention_endpoints()
del _build_named_lifecycle_v2_retention_endpoints


def _open_injected_lifecycle_v2_repository(
    store: LifecycleV2ArtifactStore,
    *,
    artifact_directory_path: str | None = None,
    retained_wire_verifier: LifecycleV2RetainedWireVerifier | None = None,
) -> _LifecycleV2Repository:
    """Test-only builder; deliberately private and without a default root."""

    return _LifecycleV2Repository(
        store,
        artifact_directory_path=artifact_directory_path,
        retained_wire_verifier=retained_wire_verifier,
    )


def lifecycle_v2_repository_non_authority_facts() -> dict[str, bool]:
    return {
        "production_store_implemented": False,
        "default_artifact_root_present": False,
        "confirmed_success_writer_present": False,
        "effect_adapter_present": False,
        "automatic_recovery_present": False,
    }


__all__ = [
    "LifecycleV2ArtifactAlreadyExists",
    "LifecycleV2ArtifactInventorySnapshot",
    "LifecycleV2ArtifactPublicationReceipt",
    "LifecycleV2ArtifactPublicationUncertain",
    "LifecycleV2ArtifactReadback",
    "LifecycleV2ArtifactStore",
    "LifecycleV2ArtifactStoreIdentity",
    "LifecycleV2AuthenticatedRetainedWireResult",
    "LifecycleV2RepositoryRejected",
    "LifecycleV2RepositoryStatus",
    "LifecycleV2RetainedWireVerifier",
    "LifecycleV2RetentionUnconfirmed",
    "LifecycleV2SlotConsumed",
    "lifecycle_v2_repository_non_authority_facts",
]
