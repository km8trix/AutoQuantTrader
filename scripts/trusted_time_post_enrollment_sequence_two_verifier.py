"""Process-private, read-only qualification of the sequence-two successor.

The public preparation seam accepts identities and fixed configuration only.
Transport construction is captured below, is delayed until the first qualified
call, and has no signing dependency or write-capable provider surface.
"""

from __future__ import annotations

import hashlib
import os
import threading
import weakref
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, fields
from enum import Enum
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, event

from apps.trusted_time_supervisor.config import validate_database_url
from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
    TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
    runtime_database_project_ref,
)
from packages.adapters.trusted_time.ed25519_anchor import (
    Ed25519TrustedTimeAnchorVerifier,
)
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS,
    SupabaseStorageAnchorCredentials,
    SupabaseStorageTrustedTimeAnchorProvider,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorProvider,
    TrustedTimeHeadAnchorRecord,
    verify_bounded_post_enrollment_start_remote_postcondition,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
    trusted_time_first_enrollment_identity_sha256,
)
from packages.persistence.postgres_tls import pinned_verify_full_connect_args
from packages.persistence.trusted_time_head_anchor import (
    PersistedTrustedTimeHeadAnchorReceipt,
    SqlTrustedTimeHeadAnchorRepository,
    TrustedTimeHeadAnchorPersistenceSnapshot,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
    _validate_admission,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
)

POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-sequence-two-verifier-v1"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS = 85_000_000_000
POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS = 8_000_000_000

_SQL_CONNECT_TIMEOUT_SECONDS = 1
_SQL_STATEMENT_TIMEOUT_MILLISECONDS = 1_000
_SQL_LOCK_TIMEOUT_MILLISECONDS = 500
_SQL_OPERATION_MARGIN_NANOSECONDS = 100_000_000
_REMOTE_OPERATION_MARGIN_NANOSECONDS = 25_000_000
_MAXIMUM_MONOTONIC_NANOSECONDS = 2**63 - 1
_ISSUER_CLOCK_BINDING_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-issuer-suspend-aware-clock-v1"
)


class TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(RuntimeError):
    """The exact read-only qualification could not be completed safely."""


def _never_authorized(_: object) -> bool:
    return False


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _configuration_projection(
    configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
) -> dict[str, object]:
    authority = configuration.authority
    credentials = configuration.credentials
    verifier = configuration.verifier
    return {
        "anchor_authority_sha256": authority.anchor_authority_sha256,
        "anchor_project_identity_sha256": authority.anchor_project_identity_sha256,
        "anchor_project_ref": authority.anchor_project_ref,
        "anchor_project_url": authority.anchor_project_url,
        "bucket_name": authority.bucket_name,
        "checkpoint_interval_seconds": authority.checkpoint_interval_seconds,
        "contract_version": POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION,
        "deployment_identity_sha256": authority.deployment_identity_sha256,
        "host_id": authority.host_id,
        "principal_id": authority.principal_id,
        "provider_principal_id": credentials.principal_id,
        "provider_project_identity_sha256": credentials.anchor_project_identity_sha256,
        "provider_project_ref": credentials.project_ref,
        "runtime_database_identity_sha256": authority.runtime_database_identity_sha256,
        "runtime_database_project_ref": authority.runtime_database_project_ref,
        "signing_key_id": verifier.signing_key_id,
        "signing_public_key_sha256": verifier.signing_public_key_sha256,
        "source_authority_sha256": authority.source_authority_sha256,
        "stale_after_seconds": authority.stale_after_seconds,
    }


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration:
    """Exact authority plus read-only credentials and public verifier."""

    authority: TrustedTimeHeadAnchorAuthority
    credentials: SupabaseStorageAnchorCredentials
    verifier: Ed25519TrustedTimeAnchorVerifier

    def __post_init__(self) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration
            or type(self.authority) is not TrustedTimeHeadAnchorAuthority
            or type(self.credentials) is not SupabaseStorageAnchorCredentials
            or type(self.verifier) is not Ed25519TrustedTimeAnchorVerifier
        ):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two read-only configuration is invalid"
            )
        try:
            self.authority.__post_init__()
            self.credentials.__post_init__()
            verifier_public_key_bytes = self.verifier._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two read-only configuration is invalid"
            ) from None
        authority = self.authority
        if (
            self.credentials.project_url != authority.anchor_project_url
            or self.credentials.project_ref != authority.anchor_project_ref
            or self.credentials.principal_id != authority.principal_id
            or self.credentials.anchor_project_identity_sha256
            != authority.anchor_project_identity_sha256
            or self.verifier.signing_key_id != authority.signing_key_id
            or self.verifier.signing_public_key_sha256 != authority.signing_public_key_sha256
            or verifier_public_key_bytes != authority.signing_public_key_bytes
        ):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two read-only configuration crosses authority"
            )

    @property
    def configuration_sha256(self) -> str:
        self.__post_init__()
        return _sha256_payload(_configuration_projection(self))

    def __repr__(self) -> str:
        return (
            "TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration("
            f"authority={self.authority!r}, credentials=<redacted>, "
            f"verifier={self.verifier!r})"
        )


@dataclass(frozen=True, slots=True)
class _PreparationBinding:
    origin_token: object
    retained_claim: object
    payload: Mapping[str, object]


class _VerifierCapability:
    __slots__ = ()

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier capability is unavailable"
        )


def _issue_verifier_capability() -> _VerifierCapability:
    return cast(
        _VerifierCapability,
        object.__new__(cast(type[Any], _VerifierCapability)),
    )


class _ResourceOwner:
    """Register cleanup before a newly constructed resource can escape."""

    __slots__ = ("_closed", "_closers", "_lock")

    def __init__(self) -> None:
        self._closed = False
        self._closers: list[tuple[object | None, Callable[[], None]]] = []
        self._lock = threading.Lock()

    def register(self, closer: Callable[[], None]) -> None:
        self._register(resource=None, closer=closer)

    def register_owned(self, resource: object, closer: Callable[[], None]) -> None:
        if resource is None:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two resource cleanup is invalid"
            )
        self._register(resource=resource, closer=closer)

    def _register(self, *, resource: object | None, closer: Callable[[], None]) -> None:
        if not callable(closer):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two resource cleanup is invalid"
            )
        with self._lock:
            if self._closed:
                with suppress(BaseException):
                    closer()
                raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                    "trusted-time sequence-two verifier resources are closed"
                )
            self._closers.append((resource, closer))

    def _owns_or_is_closed(self, resource: object) -> bool:
        with self._lock:
            return self._closed or any(registered is resource for registered, _ in self._closers)

    def close(self, *, require_success: bool) -> None:
        failures = False
        with self._lock:
            if self._closed:
                return
            self._closed = True
            closers = tuple(reversed(self._closers))
            self._closers.clear()
        for _, closer in closers:
            try:
                closer()
            except BaseException:
                failures = True
        if failures and require_success:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier cleanup is unconfirmed"
            )


def _construct_owned_resource[OwnedResource](
    *,
    owner: _ResourceOwner,
    constructor: Callable[[], OwnedResource],
    cleanup: Callable[[OwnedResource], None],
) -> OwnedResource:
    """Construct a resource and conservatively close any interrupted handoff."""

    resource: OwnedResource | None = None
    try:
        resource = constructor()
        if resource is None:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier resource is unavailable"
            )
        owner.register_owned(resource, lambda: cleanup(resource))
        return resource
    except BaseException:
        if resource is not None and not owner._owns_or_is_closed(resource):
            with suppress(BaseException):
                cleanup(resource)
        raise


class _VerificationPhaseGuard:
    __slots__ = (
        "_clock",
        "_deadline_monotonic_ns",
        "_last_observed_monotonic_ns",
        "_owner_pid",
        "_owner_thread",
    )

    def __init__(
        self,
        *,
        deadline_monotonic_ns: int,
        clock: Callable[[], int],
        owner_pid: int,
        owner_thread: threading.Thread,
    ) -> None:
        self._deadline_monotonic_ns = deadline_monotonic_ns
        self._clock = clock
        self._owner_pid = owner_pid
        self._owner_thread = owner_thread
        self._last_observed_monotonic_ns = -1
        self.require_remaining()

    @property
    def deadline_monotonic_ns(self) -> int:
        return self._deadline_monotonic_ns

    def _remaining(self) -> int:
        if os.getpid() != self._owner_pid or threading.current_thread() is not self._owner_thread:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier crossed its process or thread"
            )
        try:
            observed = self._clock()
        except BaseException:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two deadline clock failed"
            ) from None
        if (
            type(observed) is not int
            or not 0 <= observed <= _MAXIMUM_MONOTONIC_NANOSECONDS
            or observed < self._last_observed_monotonic_ns
        ):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two deadline clock is invalid"
            )
        self._last_observed_monotonic_ns = observed
        remaining = self._deadline_monotonic_ns - observed
        if remaining <= 0:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verification phase expired"
            )
        return remaining

    def require_remaining(self, minimum_remaining_ns: int = 0) -> int:
        if type(minimum_remaining_ns) is not int or minimum_remaining_ns < 0:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two operation reserve is invalid"
            )
        remaining = self._remaining()
        if remaining <= minimum_remaining_ns:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two operation cannot fit its phase"
            )
        return remaining

    def remote_timeout_seconds(self) -> float:
        remaining = self.require_remaining(_REMOTE_OPERATION_MARGIN_NANOSECONDS)
        bounded = (remaining - _REMOTE_OPERATION_MARGIN_NANOSECONDS) / 1_000_000_000
        return min(float(SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS), bounded)


class _SqlDeadlineRouter:
    __slots__ = ("_guard", "_lock", "_owner_pid", "_owner_thread")

    def __init__(self, *, owner_pid: int, owner_thread: threading.Thread) -> None:
        self._guard: _VerificationPhaseGuard | None = None
        self._lock = threading.Lock()
        self._owner_pid = owner_pid
        self._owner_thread = owner_thread

    def activate(self, guard: _VerificationPhaseGuard) -> None:
        with self._lock:
            if self._guard is not None:
                raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                    "trusted-time sequence-two SQL deadline is already active"
                )
            self._guard = guard

    def deactivate(self, guard: _VerificationPhaseGuard) -> None:
        with self._lock:
            if self._guard is guard:
                self._guard = None

    def before_cursor_execute(self, *_: object) -> None:
        with self._lock:
            guard = self._guard
        if (
            guard is None
            or os.getpid() != self._owner_pid
            or threading.current_thread() is not self._owner_thread
        ):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two SQL operation is outside its phase"
            )
        guard.require_remaining(
            _SQL_STATEMENT_TIMEOUT_MILLISECONDS * 1_000_000 + _SQL_OPERATION_MARGIN_NANOSECONDS
        )


class _DeadlineBoundReadOnlyProvider:
    __slots__ = ("_guard", "_provider")

    def __init__(self, provider: SupabaseStorageTrustedTimeAnchorProvider) -> None:
        self._provider = provider
        self._guard: _VerificationPhaseGuard | None = None

    def activate(self, guard: _VerificationPhaseGuard) -> None:
        if self._guard is not None:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two provider deadline is already active"
            )
        self._guard = guard

    def deactivate(self, guard: _VerificationPhaseGuard) -> None:
        if self._guard is guard:
            self._guard = None

    def _call(self, method_name: str, **kwargs: object) -> object:
        guard = self._guard
        if guard is None:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two provider operation is outside its phase"
            )
        timeout = guard.remote_timeout_seconds()
        self._provider._timeout_seconds = timeout
        try:
            method = getattr(self._provider, method_name)
            return method(**kwargs)
        finally:
            guard.require_remaining()

    def attest_identity(self) -> object:
        return self._call("attest_identity")

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]:
        result = self._call("list_object_names", bucket_name=bucket_name, prefix=prefix)
        return result  # type: ignore[return-value]

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        result = self._call(
            "list_object_names_page",
            bucket_name=bucket_name,
            prefix=prefix,
            offset=offset,
            limit=limit,
        )
        return result  # type: ignore[return-value]

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        result = self._call(
            "list_sequence_object_names",
            bucket_name=bucket_name,
            prefix=prefix,
            anchor_sequence=anchor_sequence,
        )
        return result  # type: ignore[return-value]

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        result = self._call(
            "download_object",
            bucket_name=bucket_name,
            object_name=object_name,
        )
        return result  # type: ignore[return-value]


class _ProductionResources:
    __slots__ = (
        "_authority",
        "_provider",
        "_repository",
        "_router",
        "_snapshot",
        "_verifier",
    )

    def __init__(
        self,
        *,
        authority: TrustedTimeHeadAnchorAuthority,
        repository: SqlTrustedTimeHeadAnchorRepository,
        provider: _DeadlineBoundReadOnlyProvider,
        verifier: Ed25519TrustedTimeAnchorVerifier,
        router: _SqlDeadlineRouter,
    ) -> None:
        self._authority = authority
        self._repository = repository
        self._provider = provider
        self._verifier = verifier
        self._router = router
        self._snapshot: TrustedTimeHeadAnchorPersistenceSnapshot | None = None

    def _replace_snapshot(
        self,
        guard: _VerificationPhaseGuard,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        guard.require_remaining(
            _SQL_CONNECT_TIMEOUT_SECONDS * 1_000_000_000 + _SQL_OPERATION_MARGIN_NANOSECONDS
        )
        authority = self._authority
        previous = self._snapshot
        replacement: TrustedTimeHeadAnchorPersistenceSnapshot | None = None
        try:
            replacement = self._repository.load_head_anchor_startup_snapshot(
                host_id=authority.host_id,
                deployment_identity_sha256=authority.deployment_identity_sha256,
                runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
                anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
                anchor_project_ref=authority.anchor_project_ref,
                bucket_name=authority.bucket_name,
                principal_id=authority.principal_id,
            )
            guard.require_remaining()
            if previous is replacement:
                return replacement
            self._snapshot = replacement
            if previous is not None:
                self._repository.discard_head_anchor_snapshot(previous)
            return replacement
        except BaseException:
            if replacement is not None and replacement is not previous:
                if self._snapshot is replacement:
                    if previous is not None:
                        with suppress(BaseException):
                            self._repository.discard_head_anchor_snapshot(previous)
                else:
                    with suppress(BaseException):
                        self._repository.discard_head_anchor_snapshot(replacement)
            raise

    def discard_snapshot(self) -> None:
        snapshot = self._snapshot
        self._snapshot = None
        if snapshot is not None:
            self._repository.discard_head_anchor_snapshot(snapshot)

    @staticmethod
    def _require_terminal(
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> tuple[PersistedTrustedTimeHeadAnchorReceipt, TrustedTimeHeadAnchorRecord, int]:
        receipt = snapshot.confirmed_anchor_receipt
        tip = snapshot.authenticated_journal_tip
        terminal_ordinal = getattr(tip, "confirmed_anchor_local_transition_ordinal", None)
        if (
            snapshot.complete_replay is not True
            or snapshot.confirmed_anchor_count != 2
            or snapshot.pending_intent is not None
            or receipt is None
            or type(snapshot.local_transition_count) is not int
            or snapshot.local_transition_count < 2
            or type(terminal_ordinal) is not int
            or terminal_ordinal < 2
            or terminal_ordinal > snapshot.local_transition_count
            or getattr(tip, "confirmed_anchor_count", None) != 2
            or getattr(tip, "confirmed_anchor_tip", None) != receipt.intent.record
            or getattr(tip, "local_transition_count", None) != snapshot.local_transition_count
            or getattr(tip, "current_local_host_head_sha256", None)
            != snapshot.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
        try:
            receipt.__post_init__()
            record = receipt.intent.record
            record.__post_init__()
        except BaseException:
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed() from None
        if (
            record.anchor_sequence != 2
            or record.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
        return receipt, record, terminal_ordinal

    @staticmethod
    def _require_probe_suffix(
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
        *,
        record: TrustedTimeHeadAnchorRecord,
        terminal_ordinal: int,
    ) -> None:
        transition = getattr(snapshot.authenticated_journal_tip, "current_transition", None)
        suffix_count = snapshot.local_transition_count - terminal_ordinal
        record_epoch = tuple(
            getattr(record, field_name)
            for field_name in (
                "source_id",
                "source_authority_sha256",
                "policy_sha256",
                "persistence_contract_version",
                "epoch_sequence",
                "monitor_epoch_id",
                "epoch_sha256",
            )
        )
        transition_epoch = tuple(
            getattr(transition, field_name, None)
            for field_name in (
                "source_id",
                "source_authority_sha256",
                "policy_sha256",
                "persistence_contract_version",
                "epoch_sequence",
                "monitor_epoch_id",
                "epoch_sha256",
            )
        )
        if (
            suffix_count < 0
            or transition_epoch != record_epoch
            or getattr(transition, "evaluation_sequence", None)
            != record.evaluation_sequence + suffix_count
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()

    def verify(
        self,
        guard: _VerificationPhaseGuard,
    ) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
        self._router.activate(guard)
        self._provider.activate(guard)
        try:
            snapshot = self._replace_snapshot(guard)
            receipt, record, terminal_ordinal = self._require_terminal(snapshot)
            self._require_probe_suffix(
                snapshot,
                record=record,
                terminal_ordinal=terminal_ordinal,
            )
            authority = self._authority
            if (
                record.anchor_authority_sha256 != authority.anchor_authority_sha256
                or record.deployment_identity_sha256 != authority.deployment_identity_sha256
                or record.runtime_database_identity_sha256
                != authority.runtime_database_identity_sha256
                or record.anchor_project_identity_sha256 != authority.anchor_project_identity_sha256
                or record.anchor_project_ref != authority.anchor_project_ref
                or record.source_authority_sha256 != authority.source_authority_sha256
                or record.signing_key_id != authority.signing_key_id
                or record.signing_public_key_sha256 != authority.signing_public_key_sha256
                or record.host_id != authority.host_id
                or record.principal_id != authority.principal_id
                or record.bucket_name != authority.bucket_name
                or record.checkpoint_interval_seconds
                != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                or type(record.previous_anchor_sha256) is not str
            ):
                raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
            initial_count = snapshot.local_transition_count
            initial_head = snapshot.current_host_head_sha256
            namespace_sha256 = verify_bounded_post_enrollment_start_remote_postcondition(
                snapshot.authenticated_journal_tip,
                provider=cast(TrustedTimeHeadAnchorProvider, self._provider),
                verifier=self._verifier,
                signing_key_id=authority.signing_key_id,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
                anchor_authority_sha256=authority.anchor_authority_sha256,
            )
            final_snapshot = self._replace_snapshot(guard)
            final_receipt, final_record, final_ordinal = self._require_terminal(final_snapshot)
            self._require_probe_suffix(
                final_snapshot,
                record=final_record,
                terminal_ordinal=final_ordinal,
            )
            if (
                final_receipt != receipt
                or final_receipt.intent != receipt.intent
                or final_record != record
                or final_ordinal != terminal_ordinal
                or final_snapshot.local_transition_count < initial_count
                or (
                    final_snapshot.local_transition_count == initial_count
                    and final_snapshot.current_host_head_sha256 != initial_head
                )
            ):
                raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
            result = TrustedTimeHeadAnchorPostEnrollmentStartPostcondition(
                anchor_sequence=record.anchor_sequence,
                checkpoint_reason=record.checkpoint_reason,
                confirmed_anchor_count=final_snapshot.confirmed_anchor_count,
                local_transition_count=final_snapshot.local_transition_count,
                confirmed_anchor_local_transition_ordinal=final_ordinal,
                remote_object_count=2,
                predecessor_anchor_sha256=record.previous_anchor_sha256,
                current_host_head_sha256=record.current_host_head_sha256,
                current_anchor_sha256=record.byte_sha256,
                current_anchor_semantic_sha256=record.semantic_sha256,
                anchor_intent_semantic_sha256=receipt.intent.semantic_sha256,
                candidate_remote_readback_sha256=receipt.readback_bytes_sha256,
                receipt_semantic_sha256=receipt.semantic_sha256,
                remote_namespace_sha256=namespace_sha256,
                anchor_authority_sha256=authority.anchor_authority_sha256,
                deployment_identity_sha256=authority.deployment_identity_sha256,
                runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
                anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
                source_authority_sha256=authority.source_authority_sha256,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                host_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="host", value=authority.host_id
                ),
                principal_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="principal", value=authority.principal_id
                ),
                bucket_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="bucket", value=authority.bucket_name
                ),
                full_audit_completed=True,
                pending_intent_present=False,
            )
            guard.require_remaining()
            return result
        except TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed:
            raise
        except BaseException:
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed() from None
        finally:
            self._provider.deactivate(guard)
            self._router.deactivate(guard)


def _create_production_resources(
    *,
    database_url: str,
    configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
    owner: _ResourceOwner,
    owner_pid: int,
    owner_thread: threading.Thread,
    initial_guard: _VerificationPhaseGuard,
) -> _ProductionResources:
    initial_guard.require_remaining(
        _SQL_CONNECT_TIMEOUT_SECONDS * 1_000_000_000 + _SQL_OPERATION_MARGIN_NANOSECONDS
    )
    tls = pinned_verify_full_connect_args(database_url, required=True)
    router = _SqlDeadlineRouter(owner_pid=owner_pid, owner_thread=owner_thread)
    engine = _construct_owned_resource(
        owner=owner,
        constructor=lambda: create_engine(
            database_url,
            connect_args={
                "connect_timeout": _SQL_CONNECT_TIMEOUT_SECONDS,
                **tls,
                "options": (
                    f"-c statement_timeout={_SQL_STATEMENT_TIMEOUT_MILLISECONDS} "
                    f"-c lock_timeout={_SQL_LOCK_TIMEOUT_MILLISECONDS}"
                ),
            },
            max_overflow=0,
            pool_pre_ping=False,
            pool_size=1,
            pool_timeout=float(_SQL_CONNECT_TIMEOUT_SECONDS),
        ),
        cleanup=lambda candidate: candidate.dispose(),
    )
    event.listen(engine, "before_cursor_execute", router.before_cursor_execute)
    authority = configuration.authority
    repository = SqlTrustedTimeHeadAnchorRepository(
        engine,
        verifier=configuration.verifier,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        signing_key_id=authority.signing_key_id,
        signing_public_key_sha256=authority.signing_public_key_sha256,
    )
    provider = _construct_owned_resource(
        owner=owner,
        constructor=lambda: SupabaseStorageTrustedTimeAnchorProvider(
            credentials=configuration.credentials,
            timeout_seconds=initial_guard.remote_timeout_seconds(),
        ),
        cleanup=lambda candidate: candidate.close(),
    )
    read_only_provider = _DeadlineBoundReadOnlyProvider(provider)
    resources = _ProductionResources(
        authority=authority,
        repository=repository,
        provider=read_only_provider,
        verifier=configuration.verifier,
        router=router,
    )
    owner.register(resources.discard_snapshot)
    return resources


def _production_verify_once(
    resources: object,
    guard: _VerificationPhaseGuard,
) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
    if type(resources) is not _ProductionResources:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier resources are invalid"
        )
    return resources.verify(guard)


def _retained_from_admission(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    try:
        action_fence = cast(Any, admission._action_fence)
        retained = action_fence._claimed_fence._handoff.retained_claim
    except BaseException:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two retained claim is unavailable"
        ) from None
    if type(retained) is not RetainedTrustedTimePostEnrollmentStartClaim:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two retained claim is unavailable"
        )
    return retained


def _require_configuration_matches_claim(
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
) -> None:
    identities = retained.claim.approval.confirmed_enrollment.identities
    authority = configuration.authority
    expected = {
        "anchor_authority_sha256": authority.anchor_authority_sha256,
        "anchor_project_identity_sha256": authority.anchor_project_identity_sha256,
        "bucket_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="bucket", value=authority.bucket_name
        ),
        "deployment_identity_sha256": authority.deployment_identity_sha256,
        "host_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="host", value=authority.host_id
        ),
        "principal_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="principal", value=authority.principal_id
        ),
        "runtime_database_identity_sha256": authority.runtime_database_identity_sha256,
        "signing_public_key_sha256": authority.signing_public_key_sha256,
        "source_authority_sha256": authority.source_authority_sha256,
    }
    if identities.payload() != expected:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two configuration conflicts with the retained claim"
        )


def _prepare_exact_binding(
    *,
    admission: object,
    topology_issuer: object,
    choreography_lease: object,
    recovery_retention_capability: object,
    action_deadline_monotonic_ns: int,
    artifact_directory: Path,
    ignored_root: Path,
    configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
) -> _PreparationBinding:
    if (
        type(admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
        or type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
        or choreography_lease is None
        or recovery_retention_capability is None
        or type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or artifact_directory != ignored_root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two preparation tuple is invalid"
        )
    _validate_admission(admission)
    retained = _retained_from_admission(admission)
    retained.__post_init__()
    _require_configuration_matches_claim(retained, configuration)
    checkpoint = topology_issuer._require_armed_recovery_outcome_retention(
        choreography_lease,
        recovery_retention_capability,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    topology_issuer._require_active_choreography_lease(choreography_lease)
    if (
        not revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        or type(action_deadline_monotonic_ns) is not int
        or action_deadline_monotonic_ns
        <= POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS
        or action_deadline_monotonic_ns > checkpoint.deadline_monotonic_ns
        or checkpoint.observed_monotonic_ns
        >= action_deadline_monotonic_ns
        - POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS
    ):
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two preparation deadline or claim is invalid"
        )
    topology_issuer._require_active_choreography_lease(choreography_lease)
    claim = retained.claim
    payload = {
        "admission_sha256": admission.admission_sha256,
        "approval_sha256": admission.approval_sha256,
        "claim_sha256": admission.claim_sha256,
        "claimed_action_fence_sha256": admission.claimed_action_fence_sha256,
        "final_action_observation_sha256": admission.final_action_observation_sha256,
        "final_action_snapshot_sha256": admission.final_action_snapshot_sha256,
        "final_action_stable_topology_sha256": (admission.final_action_stable_topology_sha256),
        "operation_id": admission.operation_id,
        "proposed_launch": claim.approval.proposed_launch.payload(),
        "retained_claim_artifact_sha256": admission.retained_claim_artifact_sha256,
        "retained_claim_file_identity": list(retained.file_identity),
        "session_sha256": admission.session_sha256,
    }
    return _PreparationBinding(
        origin_token=admission._capability,
        retained_claim=retained,
        payload=payload,
    )


def _revalidate_exact_call(
    *,
    binding: _PreparationBinding,
    admission: object,
    topology_issuer: object,
    choreography_lease: object,
    recovery_retention_capability: object,
    action_deadline_monotonic_ns: int,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    del recovery_retention_capability
    if (
        type(admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
        or type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
        or type(binding.retained_claim) is not RetainedTrustedTimePostEnrollmentStartClaim
    ):
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verification tuple is invalid"
        )
    _validate_admission(admission)
    topology_issuer._require_active_choreography_lease(choreography_lease)
    if (
        type(action_deadline_monotonic_ns) is not int
        or type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or artifact_directory != ignored_root / "trusted-time"
        or not revalidate_retained_post_enrollment_start_claim(
            binding.retained_claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    ):
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verification tuple is invalid"
        )
    topology_issuer._require_active_choreography_lease(choreography_lease)


def _postcondition_payload(
    result: TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for item in fields(result):
        value = getattr(result, item.name)
        payload[item.name] = value.value if isinstance(value, Enum) else value
    return payload


@dataclass(frozen=True, slots=True)
class _Dispatch:
    verifier_reference: weakref.ReferenceType[TrustedTimePostEnrollmentStartSequenceTwoVerifier]
    verify: Callable[..., TrustedTimeHeadAnchorPostEnrollmentStartPostcondition]
    abort: Callable[[], None]
    revoke: Callable[[], None]
    binding_digest: Callable[[], str]
    configuration_digest: Callable[[], str]
    transcript_digest: Callable[[], str | None]


class TrustedTimePostEnrollmentStartSequenceTwoVerifier:
    """Exact process-private two-call verifier with no caller-injected I/O."""

    __slots__ = ("__weakref__", "_capability")

    _capability: _VerifierCapability

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier must be prepared"
        )

    def __setattr__(self, _: str, __: object) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier is immutable"
        )

    def __delattr__(self, _: str) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier is immutable"
        )

    def _dispatch(self) -> _Dispatch:
        if type(self) is not TrustedTimePostEnrollmentStartSequenceTwoVerifier:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier is invalid"
            )
        try:
            capability = self._capability
        except BaseException:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier is invalid"
            ) from None
        return _resolve_trusted_time_post_enrollment_start_sequence_two_verifier(
            self,
            capability,
        )

    @property
    def verifier_binding_sha256(self) -> str:
        return self._dispatch().binding_digest()

    @property
    def read_only_configuration_sha256(self) -> str:
        return self._dispatch().configuration_digest()

    @property
    def verification_transcript_sha256(self) -> str | None:
        return self._dispatch().transcript_digest()

    def reauthenticate_post_enrollment_start_successor(
        self,
        *,
        admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        action_deadline_monotonic_ns: int,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
        return self._dispatch().verify(
            admission=admission,
            topology_issuer=topology_issuer,
            choreography_lease=choreography_lease,
            recovery_retention_capability=recovery_retention_capability,
            action_deadline_monotonic_ns=action_deadline_monotonic_ns,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    def abort(self) -> None:
        self._dispatch().abort()

    close = abort

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier cannot be serialized"
        )

    authority_granted = property(_never_authorized)
    operational_control_authorized = property(_never_authorized)
    readiness_authorized = property(_never_authorized)
    release_authorized = property(_never_authorized)
    sequence_2_authorized = property(_never_authorized)


def _issue_verifier() -> TrustedTimePostEnrollmentStartSequenceTwoVerifier:
    return cast(
        TrustedTimePostEnrollmentStartSequenceTwoVerifier,
        object.__new__(cast(type[Any], TrustedTimePostEnrollmentStartSequenceTwoVerifier)),
    )


def _poison_issuer(issuer: object) -> None:
    if type(issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer:
        return
    with suppress(BaseException), issuer._lifecycle_lock:
        issuer._poison_locked()


def _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer_with_registry(
    *,
    register_dispatch: Callable[
        [
            TrustedTimePostEnrollmentStartSequenceTwoVerifier,
            object,
            _Dispatch,
        ],
        None,
    ],
    preparation_validator: Callable[..., _PreparationBinding] = _prepare_exact_binding,
    call_validator: Callable[..., None] = _revalidate_exact_call,
    resource_factory: Callable[..., object] = _create_production_resources,
    verification_runner: Callable[
        [object, _VerificationPhaseGuard],
        TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
    ] = _production_verify_once,
    monotonic_ns: Callable[[], int] | None = None,
    process_id: Callable[[], int] = os.getpid,
    current_thread: Callable[[], threading.Thread] = threading.current_thread,
) -> Callable[..., TrustedTimePostEnrollmentStartSequenceTwoVerifier]:
    """Private dependency seam used only by isolated unit tests."""

    if any(
        not callable(candidate)
        for candidate in (
            preparation_validator,
            call_validator,
            resource_factory,
            verification_runner,
            process_id,
            current_thread,
        )
    ) or (monotonic_ns is not None and not callable(monotonic_ns)):
        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
            "trusted-time sequence-two verifier dependencies are invalid"
        )
    origin_lock = threading.Lock()
    consumed_origins: list[object] = []

    def prepare(
        *,
        admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        action_deadline_monotonic_ns: int,
        database_url: str,
        configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentStartSequenceTwoVerifier:
        exact_origin_established = False
        binding: _PreparationBinding | None = None
        try:
            if type(configuration) is not (
                TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration
            ):
                raise ValueError
            configuration.__post_init__()
            exact_database_url = validate_database_url(database_url)
            if (
                runtime_database_project_ref(exact_database_url)
                != configuration.authority.runtime_database_project_ref
            ):
                raise ValueError
            owner_pid = process_id()
            owner_thread = current_thread()
            if (
                type(owner_pid) is not int
                or owner_pid <= 0
                or not isinstance(owner_thread, threading.Thread)
            ):
                raise ValueError
            binding = preparation_validator(
                admission=admission,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                action_deadline_monotonic_ns=action_deadline_monotonic_ns,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
                configuration=configuration,
            )
            if type(binding) is not _PreparationBinding:
                raise ValueError
            exact_origin_established = True
            exact_monotonic_ns = monotonic_ns
            if exact_monotonic_ns is None:
                exact_monotonic_ns = topology_issuer._bound_choreography_monotonic_clock()
            if not callable(exact_monotonic_ns):
                raise ValueError
            with origin_lock:
                if any(origin is binding.origin_token for origin in consumed_origins):
                    raise ValueError
                consumed_origins.append(binding.origin_token)
            observed = exact_monotonic_ns()
            first_deadline = (
                action_deadline_monotonic_ns
                - POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS
            )
            if (
                type(observed) is not int
                or observed < 0
                or observed >= first_deadline
                or type(action_deadline_monotonic_ns) is not int
                or action_deadline_monotonic_ns > _MAXIMUM_MONOTONIC_NANOSECONDS
            ):
                raise ValueError
            configuration_sha256 = configuration.configuration_sha256
            binding_payload = {
                **dict(binding.payload),
                "action_deadline_monotonic_ns": action_deadline_monotonic_ns,
                "artifact_directory": str(artifact_directory),
                "configuration_sha256": configuration_sha256,
                "contract_version": POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION,
                "issuer_clock_contract_version": _ISSUER_CLOCK_BINDING_CONTRACT_VERSION,
                "first_verification_reserve_nanoseconds": (
                    POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS
                ),
                "ignored_root": str(ignored_root),
                "origin_pid": owner_pid,
                "origin_thread_ident": owner_thread.ident,
                "origin_thread_name": owner_thread.name,
                "recovery_capability_identity": hashlib.sha256(
                    str(id(recovery_retention_capability)).encode("ascii")
                ).hexdigest(),
                "lease_identity": hashlib.sha256(
                    str(id(choreography_lease)).encode("ascii")
                ).hexdigest(),
                "runtime_database_project_ref": (
                    configuration.authority.runtime_database_project_ref
                ),
                "second_verification_reserve_nanoseconds": (
                    POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS
                ),
            }
            binding_digest = _sha256_payload(binding_payload)
            capability = _issue_verifier_capability()
            verifier = _issue_verifier()
            object.__setattr__(verifier, "_capability", capability)
            state_lock = threading.Lock()
            state: dict[str, Any] = {
                "admission": admission,
                "binding": binding,
                "binding_digest": binding_digest,
                "calls": 0,
                "configuration": configuration,
                "configuration_digest": configuration_sha256,
                "database_url": exact_database_url,
                "deadline": action_deadline_monotonic_ns,
                "issuer": weakref.ref(topology_issuer),
                "lease": choreography_lease,
                "monotonic_clock": exact_monotonic_ns,
                "owner": None,
                "owner_pid": owner_pid,
                "owner_thread": owner_thread,
                "recovery": recovery_retention_capability,
                "resources": None,
                "result": None,
                "status": "prepared",
                "transcript": None,
            }

            def require_origin() -> None:
                if (
                    process_id() != state["owner_pid"]
                    or current_thread() is not state["owner_thread"]
                ):
                    raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                        "trusted-time sequence-two verifier crossed its process or thread"
                    )

            def bound_issuer() -> object | None:
                reference = state.get("issuer")
                return reference() if isinstance(reference, weakref.ReferenceType) else None

            def cleanup(*, require_success: bool) -> None:
                owner = state.get("owner")
                state["resources"] = None
                state["owner"] = None
                state["database_url"] = None
                state["configuration"] = None
                state["monotonic_clock"] = None
                if type(owner) is _ResourceOwner:
                    owner.close(require_success=require_success)
                tombstone = {
                    "binding_digest": state["binding_digest"],
                    "configuration_digest": state["configuration_digest"],
                    "status": state["status"],
                    "transcript": state.get("transcript"),
                }
                state.clear()
                state.update(tombstone)

            def reject(*, poison: bool) -> Never:
                issuer = bound_issuer()
                state["status"] = "closed"
                cleanup(require_success=False)
                if poison:
                    _poison_issuer(issuer)
                raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                    "trusted-time sequence-two verification is unconfirmed"
                )

            def verify(**kwargs: object) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
                with state_lock:
                    try:
                        if state["status"] not in {"prepared", "first_confirmed"}:
                            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                                "trusted-time sequence-two verification is unavailable"
                            )
                        require_origin()
                        issuer = bound_issuer()
                        expected = {
                            "admission": state["admission"],
                            "topology_issuer": issuer,
                            "choreography_lease": state["lease"],
                            "recovery_retention_capability": state["recovery"],
                            "action_deadline_monotonic_ns": state["deadline"],
                            "artifact_directory": artifact_directory,
                            "ignored_root": ignored_root,
                        }
                        if set(kwargs) != set(expected) or any(
                            kwargs[name] is not value
                            if name
                            in {
                                "admission",
                                "topology_issuer",
                                "choreography_lease",
                                "recovery_retention_capability",
                            }
                            else kwargs[name] != value
                            for name, value in expected.items()
                        ):
                            reject(poison=True)
                        call_validator(binding=state["binding"], **kwargs)
                        reserve = (
                            POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS
                            if state["calls"] == 0
                            else (
                                POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS
                            )
                        )
                        phase_deadline = state["deadline"] - reserve
                        guard = _VerificationPhaseGuard(
                            deadline_monotonic_ns=phase_deadline,
                            clock=state["monotonic_clock"],
                            owner_pid=state["owner_pid"],
                            owner_thread=state["owner_thread"],
                        )
                        resources = state["resources"]
                        if resources is None:
                            owner = _ResourceOwner()
                            state["owner"] = owner
                            resources = resource_factory(
                                database_url=state["database_url"],
                                configuration=state["configuration"],
                                owner=owner,
                                owner_pid=state["owner_pid"],
                                owner_thread=state["owner_thread"],
                                initial_guard=guard,
                            )
                            state["resources"] = resources
                        result = verification_runner(resources, guard)
                        if type(result) is not (
                            TrustedTimeHeadAnchorPostEnrollmentStartPostcondition
                        ):
                            reject(poison=True)
                        result.__post_init__()
                        guard.require_remaining()
                        if state["calls"] == 0:
                            state["result"] = result
                            state["calls"] = 1
                            state["status"] = "first_confirmed"
                            return result
                        if result != state["result"]:
                            reject(poison=True)
                        transcript = _sha256_payload(
                            {
                                "contract_version": (
                                    POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION
                                ),
                                "first_and_second_results_identical": True,
                                "postcondition": _postcondition_payload(result),
                                "verification_count": 2,
                                "verifier_binding_sha256": binding_digest,
                            }
                        )
                        state["transcript"] = transcript
                        cleanup(require_success=True)
                        state["status"] = "confirmed"
                        return result
                    except TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected:
                        if state["status"] not in {"closed", "confirmed"}:
                            issuer = bound_issuer()
                            state["status"] = "closed"
                            cleanup(require_success=False)
                            _poison_issuer(issuer)
                        raise
                    except BaseException as error:
                        issuer = bound_issuer()
                        state["status"] = "closed"
                        cleanup(require_success=False)
                        _poison_issuer(issuer)
                        if not isinstance(error, Exception):
                            raise
                        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                            "trusted-time sequence-two verification is unconfirmed"
                        ) from None

            def abort() -> None:
                with state_lock:
                    if state["status"] in {"closed", "confirmed"}:
                        cleanup(require_success=False)
                        return
                    try:
                        require_origin()
                    except TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected:
                        return
                    issuer = bound_issuer()
                    state["status"] = "closed"
                    cleanup(require_success=False)
                    _poison_issuer(issuer)

            def revoke() -> None:
                """Clean a verifier lost between a successful CALL and STORE."""

                with state_lock:
                    if state["status"] in {"closed", "confirmed"}:
                        cleanup(require_success=False)
                        return
                    issuer = bound_issuer()
                    state["status"] = "closed"
                    cleanup(require_success=False)
                    _poison_issuer(issuer)

            def read_binding_digest() -> str:
                with state_lock:
                    if state["status"] not in {"closed", "confirmed"}:
                        require_origin()
                    value = state["binding_digest"]
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                            "trusted-time sequence-two verifier binding is unavailable"
                        )
                    return cast(str, value)

            def read_configuration_digest() -> str:
                with state_lock:
                    if state["status"] not in {"closed", "confirmed"}:
                        require_origin()
                    value = state["configuration_digest"]
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                            "trusted-time sequence-two configuration binding is unavailable"
                        )
                    return cast(str, value)

            def read_transcript_digest() -> str | None:
                with state_lock:
                    if state["status"] not in {"closed", "confirmed"}:
                        require_origin()
                    value = state["transcript"]
                    return value if type(value) is str else None

            dispatch = _Dispatch(
                verifier_reference=weakref.ref(verifier),
                verify=verify,
                abort=abort,
                revoke=revoke,
                binding_digest=read_binding_digest,
                configuration_digest=read_configuration_digest,
                transcript_digest=read_transcript_digest,
            )
            register_dispatch(verifier, capability, dispatch)
            return verifier
        except BaseException as error:
            if exact_origin_established:
                _poison_issuer(topology_issuer)
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier preparation failed"
            ) from None

    return prepare


def _build_trusted_time_post_enrollment_start_sequence_two_verifier_registry() -> tuple[
    Callable[
        [TrustedTimePostEnrollmentStartSequenceTwoVerifier, object],
        _Dispatch,
    ],
    Callable[..., Callable[..., TrustedTimePostEnrollmentStartSequenceTwoVerifier]],
]:
    """Seal dispatch records and the DI preparer factory in one private closure."""

    registry_lock = threading.Lock()
    registry: dict[_VerifierCapability, _Dispatch] = {}
    preparer_implementation = (
        _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer_with_registry
    )

    def register_dispatch(
        verifier: TrustedTimePostEnrollmentStartSequenceTwoVerifier,
        capability: object,
        dispatch: _Dispatch,
    ) -> None:
        if (
            type(verifier) is not TrustedTimePostEnrollmentStartSequenceTwoVerifier
            or type(capability) is not _VerifierCapability
            or type(dispatch) is not _Dispatch
            or dispatch.verifier_reference() is not verifier
        ):
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier registration is invalid"
            )
        exact_capability = cast(_VerifierCapability, capability)
        registered_dispatch: _Dispatch | None = None

        def verifier_lost(
            reference: weakref.ReferenceType[TrustedTimePostEnrollmentStartSequenceTwoVerifier],
        ) -> None:
            with registry_lock:
                current = registry.get(exact_capability)
                if current is None or current.verifier_reference is not reference:
                    return
                registry.pop(exact_capability, None)
            with suppress(BaseException):
                current.revoke()

        registered_reference = weakref.ref(verifier, verifier_lost)
        registered_dispatch = _Dispatch(
            verifier_reference=registered_reference,
            verify=dispatch.verify,
            abort=dispatch.abort,
            revoke=dispatch.revoke,
            binding_digest=dispatch.binding_digest,
            configuration_digest=dispatch.configuration_digest,
            transcript_digest=dispatch.transcript_digest,
        )
        with registry_lock:
            if exact_capability in registry:
                raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                    "trusted-time sequence-two verifier registration was replayed"
                )
            registry[exact_capability] = registered_dispatch

    def resolve_dispatch(
        verifier: TrustedTimePostEnrollmentStartSequenceTwoVerifier,
        capability: object,
    ) -> _Dispatch:
        if type(capability) is not _VerifierCapability:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier is unavailable"
            )
        exact_capability = cast(_VerifierCapability, capability)
        with registry_lock:
            dispatch = registry.get(exact_capability)
        if dispatch is None or dispatch.verifier_reference() is not verifier:
            raise TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected(
                "trusted-time sequence-two verifier is unavailable"
            )
        return dispatch

    def build_preparer(
        *,
        preparation_validator: Callable[..., _PreparationBinding] = _prepare_exact_binding,
        call_validator: Callable[..., None] = _revalidate_exact_call,
        resource_factory: Callable[..., object] = _create_production_resources,
        verification_runner: Callable[
            [object, _VerificationPhaseGuard],
            TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
        ] = _production_verify_once,
        monotonic_ns: Callable[[], int] | None = None,
        process_id: Callable[[], int] = os.getpid,
        current_thread: Callable[[], threading.Thread] = threading.current_thread,
    ) -> Callable[..., TrustedTimePostEnrollmentStartSequenceTwoVerifier]:
        return preparer_implementation(
            register_dispatch=register_dispatch,
            preparation_validator=preparation_validator,
            call_validator=call_validator,
            resource_factory=resource_factory,
            verification_runner=verification_runner,
            monotonic_ns=monotonic_ns,
            process_id=process_id,
            current_thread=current_thread,
        )

    return resolve_dispatch, build_preparer


(
    _resolve_trusted_time_post_enrollment_start_sequence_two_verifier,
    _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer,
) = _build_trusted_time_post_enrollment_start_sequence_two_verifier_registry()
del _build_trusted_time_post_enrollment_start_sequence_two_verifier_registry


prepare_trusted_time_post_enrollment_start_sequence_two_verifier = (
    _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer()
)


__all__ = [
    "POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION",
    "TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration",
    "TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected",
    "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
    "prepare_trusted_time_post_enrollment_start_sequence_two_verifier",
]
