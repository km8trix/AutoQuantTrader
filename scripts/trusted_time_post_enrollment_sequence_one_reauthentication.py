"""One-shot, process-private read-only sequence-one reauthentication.

The public preparation seam accepts only an exact database URL, non-secret
authority, read-only Supabase credentials, a public Ed25519 verifier, and the
already-authenticated choreography tuple.  SQL and provider resources are
created lazily on the sole reauthentication call.  This module has no signer,
upload port, CLI, runtime-launch surface, or trading authority.
"""

from __future__ import annotations

import hashlib
import os
import threading
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, event

from apps.trusted_time_supervisor.config import validate_database_url
from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed,
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
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
    verify_bounded_first_enrollment_remote_postcondition,
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
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
)

POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-sequence-one-read-only-reauthentication-v1"
)
POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS = 260_000_000_000

_SQL_CONNECT_TIMEOUT_SECONDS = 1
_SQL_STATEMENT_TIMEOUT_MILLISECONDS = 1_000
_SQL_LOCK_TIMEOUT_MILLISECONDS = 500
_SQL_OPERATION_MARGIN_NANOSECONDS = 100_000_000
_REMOTE_OPERATION_MARGIN_NANOSECONDS = 25_000_000
_MAXIMUM_MONOTONIC_NANOSECONDS = 2**63 - 1
_ISSUER_CLOCK_BINDING_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-issuer-suspend-aware-clock-v1"
)


class TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(RuntimeError):
    """The one-shot read-only sequence-one proof could not be completed."""


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


@dataclass(frozen=True, slots=True)
class _ReadOnlyConfiguration:
    authority: TrustedTimeHeadAnchorAuthority
    credentials: SupabaseStorageAnchorCredentials
    verifier: Ed25519TrustedTimeAnchorVerifier

    def __post_init__(self) -> None:
        if (
            type(self) is not _ReadOnlyConfiguration
            or type(self.authority) is not TrustedTimeHeadAnchorAuthority
            or type(self.credentials) is not SupabaseStorageAnchorCredentials
            or type(self.verifier) is not Ed25519TrustedTimeAnchorVerifier
        ):
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one read-only configuration is invalid"
            )
        try:
            self.authority.__post_init__()
            self.credentials.__post_init__()
            public_key_bytes = self.verifier._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one read-only configuration is invalid"
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
            or public_key_bytes != authority.signing_public_key_bytes
        ):
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one read-only configuration crosses authority"
            )

    @property
    def configuration_sha256(self) -> str:
        self.__post_init__()
        authority = self.authority
        credentials = self.credentials
        verifier = self.verifier
        return _sha256_payload(
            {
                "anchor_authority_sha256": authority.anchor_authority_sha256,
                "anchor_project_identity_sha256": (authority.anchor_project_identity_sha256),
                "anchor_project_ref": authority.anchor_project_ref,
                "anchor_project_url": authority.anchor_project_url,
                "bucket_name": authority.bucket_name,
                "checkpoint_interval_seconds": authority.checkpoint_interval_seconds,
                "contract_version": (
                    POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION
                ),
                "deployment_identity_sha256": authority.deployment_identity_sha256,
                "host_id": authority.host_id,
                "principal_id": authority.principal_id,
                "provider_principal_id": credentials.principal_id,
                "provider_project_identity_sha256": (credentials.anchor_project_identity_sha256),
                "provider_project_ref": credentials.project_ref,
                "runtime_database_identity_sha256": (authority.runtime_database_identity_sha256),
                "runtime_database_project_ref": authority.runtime_database_project_ref,
                "signing_key_id": verifier.signing_key_id,
                "signing_public_key_sha256": verifier.signing_public_key_sha256,
                "source_authority_sha256": authority.source_authority_sha256,
                "stale_after_seconds": authority.stale_after_seconds,
            }
        )

    def __repr__(self) -> str:
        return (
            "_ReadOnlyConfiguration("
            f"authority={self.authority!r}, credentials=<redacted>, "
            f"verifier={self.verifier!r})"
        )


@dataclass(frozen=True, slots=True)
class _PreparationBinding:
    origin_sha256: str
    payload: dict[str, object]

    def __post_init__(self) -> None:
        if not _is_sha256(self.origin_sha256) or type(self.payload) is not dict:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one preparation binding is invalid"
            )


class _IssuerCapability:
    __slots__ = ()

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer capability is unavailable"
        )


def _issue_capability() -> _IssuerCapability:
    return cast(_IssuerCapability, object.__new__(cast(type[Any], _IssuerCapability)))


class _ResourceOwner:
    """Own cleanup before a lazily constructed resource can escape."""

    __slots__ = ("_closed", "_closers", "_lock")

    def __init__(self) -> None:
        self._closed = False
        self._closers: list[tuple[object | None, Callable[[], None]]] = []
        self._lock = threading.Lock()

    def register(self, closer: Callable[[], None]) -> None:
        self._register(resource=None, closer=closer)

    def register_owned(self, resource: object, closer: Callable[[], None]) -> None:
        if resource is None:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one resource cleanup is invalid"
            )
        self._register(resource=resource, closer=closer)

    def _register(self, *, resource: object | None, closer: Callable[[], None]) -> None:
        if not callable(closer):
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one resource cleanup is invalid"
            )
        with self._lock:
            if self._closed:
                with suppress(BaseException):
                    closer()
                raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                    "trusted-time sequence-one resources are closed"
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
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one resource cleanup is unconfirmed"
            )


def _construct_owned_resource[OwnedResource](
    *,
    owner: _ResourceOwner,
    constructor: Callable[[], OwnedResource],
    cleanup: Callable[[OwnedResource], None],
) -> OwnedResource:
    resource: OwnedResource | None = None
    try:
        resource = constructor()
        if resource is None:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one resource is unavailable"
            )
        owner.register_owned(resource, lambda: cleanup(resource))
        return resource
    except BaseException:
        if resource is not None and not owner._owns_or_is_closed(resource):
            with suppress(BaseException):
                cleanup(resource)
        raise


class _ReauthenticationPhaseGuard:
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
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer crossed its process or thread"
            )
        try:
            observed = self._clock()
        except BaseException:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one deadline clock failed"
            ) from None
        if (
            type(observed) is not int
            or not 0 <= observed <= _MAXIMUM_MONOTONIC_NANOSECONDS
            or observed < self._last_observed_monotonic_ns
        ):
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one deadline clock is invalid"
            )
        self._last_observed_monotonic_ns = observed
        remaining = self._deadline_monotonic_ns - observed
        if remaining <= 0:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one reauthentication phase expired"
            )
        return remaining

    def require_remaining(self, minimum_remaining_ns: int = 0) -> int:
        if type(minimum_remaining_ns) is not int or minimum_remaining_ns < 0:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one operation reserve is invalid"
            )
        remaining = self._remaining()
        if remaining <= minimum_remaining_ns:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one operation cannot fit its phase"
            )
        return remaining

    def remote_timeout_seconds(self) -> float:
        remaining = self.require_remaining(_REMOTE_OPERATION_MARGIN_NANOSECONDS)
        bounded = (remaining - _REMOTE_OPERATION_MARGIN_NANOSECONDS) / 1_000_000_000
        return min(float(SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS), bounded)


class _SqlDeadlineRouter:
    __slots__ = ("_guard", "_lock", "_owner_pid", "_owner_thread")

    def __init__(self, *, owner_pid: int, owner_thread: threading.Thread) -> None:
        self._guard: _ReauthenticationPhaseGuard | None = None
        self._lock = threading.Lock()
        self._owner_pid = owner_pid
        self._owner_thread = owner_thread

    def activate(self, guard: _ReauthenticationPhaseGuard) -> None:
        with self._lock:
            if self._guard is not None:
                raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                    "trusted-time sequence-one SQL deadline is already active"
                )
            self._guard = guard

    def deactivate(self, guard: _ReauthenticationPhaseGuard) -> None:
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
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one SQL operation is outside its phase"
            )
        guard.require_remaining(
            _SQL_STATEMENT_TIMEOUT_MILLISECONDS * 1_000_000 + _SQL_OPERATION_MARGIN_NANOSECONDS
        )


class _DeadlineBoundReadOnlyProvider:
    """Expose only the remote read methods used by the bounded audit."""

    __slots__ = ("_guard", "_provider")

    def __init__(self, provider: SupabaseStorageTrustedTimeAnchorProvider) -> None:
        self._provider = provider
        self._guard: _ReauthenticationPhaseGuard | None = None

    def activate(self, guard: _ReauthenticationPhaseGuard) -> None:
        if self._guard is not None:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one provider deadline is already active"
            )
        self._guard = guard

    def deactivate(self, guard: _ReauthenticationPhaseGuard) -> None:
        if self._guard is guard:
            self._guard = None

    def _call(self, method_name: str, **kwargs: object) -> object:
        guard = self._guard
        if guard is None:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one provider operation is outside its phase"
            )
        self._provider._timeout_seconds = guard.remote_timeout_seconds()
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
        guard: _ReauthenticationPhaseGuard,
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
                runtime_database_identity_sha256=(authority.runtime_database_identity_sha256),
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
            or snapshot.confirmed_anchor_count != 1
            or snapshot.pending_intent is not None
            or receipt is None
            or type(snapshot.local_transition_count) is not int
            or snapshot.local_transition_count < 1
            or type(terminal_ordinal) is not int
            or terminal_ordinal != snapshot.local_transition_count
            or getattr(tip, "confirmed_anchor_count", None) != 1
            or getattr(tip, "confirmed_anchor_tip", None) != receipt.intent.record
            or getattr(tip, "local_transition_count", None) != snapshot.local_transition_count
            or getattr(tip, "current_local_host_head_sha256", None)
            != snapshot.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(None)
        try:
            receipt.__post_init__()
            record = receipt.intent.record
            record.__post_init__()
        except BaseException:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                None
            ) from None
        if (
            record.anchor_sequence != 1
            or record.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
            or record.previous_anchor_sha256 is not None
            or record.previous_anchored_host_head_sha256 is not None
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(None)
        return receipt, record, terminal_ordinal

    def verify(
        self,
        guard: _ReauthenticationPhaseGuard,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
        self._router.activate(guard)
        try:
            self._provider.activate(guard)
            try:
                snapshot = self._replace_snapshot(guard)
                receipt, record, terminal_ordinal = self._require_terminal(snapshot)
                authority = self._authority
                if (
                    record.anchor_authority_sha256 != authority.anchor_authority_sha256
                    or record.deployment_identity_sha256 != authority.deployment_identity_sha256
                    or record.runtime_database_identity_sha256
                    != authority.runtime_database_identity_sha256
                    or record.anchor_project_identity_sha256
                    != authority.anchor_project_identity_sha256
                    or record.anchor_project_ref != authority.anchor_project_ref
                    or record.source_authority_sha256 != authority.source_authority_sha256
                    or record.signing_key_id != authority.signing_key_id
                    or record.signing_public_key_sha256 != authority.signing_public_key_sha256
                    or record.host_id != authority.host_id
                    or record.principal_id != authority.principal_id
                    or record.bucket_name != authority.bucket_name
                    or record.checkpoint_interval_seconds
                    != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                    or record.current_host_head_sha256 != snapshot.current_host_head_sha256
                ):
                    raise (
                        TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(None)
                    )
                namespace_sha256 = verify_bounded_first_enrollment_remote_postcondition(
                    snapshot.authenticated_journal_tip,
                    provider=cast(TrustedTimeHeadAnchorProvider, self._provider),
                    verifier=self._verifier,
                    signing_key_id=authority.signing_key_id,
                    signing_public_key_sha256=authority.signing_public_key_sha256,
                    checkpoint_interval_seconds=(
                        TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                    ),
                    anchor_authority_sha256=authority.anchor_authority_sha256,
                )
                final_snapshot = self._replace_snapshot(guard)
                final_receipt, final_record, final_ordinal = self._require_terminal(final_snapshot)
                if (
                    final_receipt != receipt
                    or final_receipt.intent != receipt.intent
                    or final_record != record
                    or final_ordinal != terminal_ordinal
                    or final_snapshot.authenticated_journal_tip
                    != snapshot.authenticated_journal_tip
                    or final_snapshot.local_transition_count != snapshot.local_transition_count
                    or final_snapshot.current_host_head_sha256 != snapshot.current_host_head_sha256
                ):
                    raise (
                        TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(None)
                    )
                result = TrustedTimeHeadAnchorFirstEnrollmentPostcondition(
                    anchor_sequence=record.anchor_sequence,
                    checkpoint_reason=record.checkpoint_reason,
                    confirmed_anchor_count=final_snapshot.confirmed_anchor_count,
                    local_transition_count=final_snapshot.local_transition_count,
                    confirmed_anchor_local_transition_ordinal=final_ordinal,
                    remote_object_count=1,
                    current_host_head_sha256=record.current_host_head_sha256,
                    current_anchor_sha256=record.byte_sha256,
                    current_anchor_semantic_sha256=record.semantic_sha256,
                    anchor_intent_semantic_sha256=receipt.intent.semantic_sha256,
                    candidate_remote_readback_sha256=receipt.readback_bytes_sha256,
                    receipt_semantic_sha256=receipt.semantic_sha256,
                    remote_namespace_sha256=namespace_sha256,
                    anchor_authority_sha256=authority.anchor_authority_sha256,
                    deployment_identity_sha256=authority.deployment_identity_sha256,
                    runtime_database_identity_sha256=(authority.runtime_database_identity_sha256),
                    anchor_project_identity_sha256=(authority.anchor_project_identity_sha256),
                    source_authority_sha256=authority.source_authority_sha256,
                    signing_public_key_sha256=authority.signing_public_key_sha256,
                    host_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                        kind="host", value=authority.host_id
                    ),
                    principal_identity_sha256=(
                        trusted_time_first_enrollment_identity_sha256(
                            kind="principal", value=authority.principal_id
                        )
                    ),
                    bucket_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                        kind="bucket", value=authority.bucket_name
                    ),
                    full_audit_completed=True,
                    pending_intent_present=False,
                )
                guard.require_remaining()
                return result
            finally:
                self._provider.deactivate(guard)
        except TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed:
            raise
        except BaseException:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                None
            ) from None
        finally:
            self._router.deactivate(guard)


def _create_production_resources(
    *,
    database_url: str,
    configuration: _ReadOnlyConfiguration,
    owner: _ResourceOwner,
    owner_pid: int,
    owner_thread: threading.Thread,
    initial_guard: _ReauthenticationPhaseGuard,
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
                    f"-c lock_timeout={_SQL_LOCK_TIMEOUT_MILLISECONDS} "
                    "-c default_transaction_read_only=on"
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
    resources = _ProductionResources(
        authority=authority,
        repository=repository,
        provider=_DeadlineBoundReadOnlyProvider(provider),
        verifier=configuration.verifier,
        router=router,
    )
    owner.register(resources.discard_snapshot)
    return resources


def _production_reauthenticate_once(
    resources: object,
    guard: _ReauthenticationPhaseGuard,
) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
    if type(resources) is not _ProductionResources:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one resources are invalid"
        )
    return resources.verify(guard)


def _prepare_exact_binding(
    *,
    topology_issuer: object,
    choreography_lease: object,
    recovery_retention_capability: object,
    action_deadline_monotonic_ns: int,
    artifact_directory: Path,
    ignored_root: Path,
    configuration: _ReadOnlyConfiguration,
) -> _PreparationBinding:
    if (
        type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
        or choreography_lease is None
        or recovery_retention_capability is None
        or type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or artifact_directory != ignored_root / "trusted-time"
        or type(configuration) is not _ReadOnlyConfiguration
    ):
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one preparation tuple is invalid"
        )
    configuration.__post_init__()
    checkpoint = topology_issuer._require_unbound_recovery_retention_preparation(
        choreography_lease,
        recovery_retention_capability,
    )
    topology_issuer._require_active_choreography_lease(choreography_lease)
    phase_deadline = (
        action_deadline_monotonic_ns
        - POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
    )
    if (
        type(action_deadline_monotonic_ns) is not int
        or action_deadline_monotonic_ns > _MAXIMUM_MONOTONIC_NANOSECONDS
        or action_deadline_monotonic_ns != checkpoint.deadline_monotonic_ns
        or checkpoint.observed_monotonic_ns >= phase_deadline
    ):
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one preparation deadline is invalid"
        )
    topology_issuer._require_active_choreography_lease(choreography_lease)
    origin_payload = {
        "action_deadline_monotonic_ns": action_deadline_monotonic_ns,
        "artifact_directory": str(artifact_directory),
        "choreography_started_monotonic_ns": checkpoint.started_monotonic_ns,
        "ignored_root": str(ignored_root),
        "issuer_session_sha256": topology_issuer._session_sha256,
        "lease_identity": id(choreography_lease),
        "recovery_capability_identity": id(recovery_retention_capability),
    }
    return _PreparationBinding(
        origin_sha256=_sha256_payload(origin_payload),
        payload={
            **origin_payload,
            "configuration_sha256": configuration.configuration_sha256,
        },
    )


def _revalidate_exact_call(
    *,
    topology_issuer: object,
    choreography_lease: object,
    recovery_retention_capability: object,
    action_deadline_monotonic_ns: int,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    if (
        type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
        or type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or artifact_directory != ignored_root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one call tuple is invalid"
        )
    checkpoint = topology_issuer._require_unbound_recovery_retention_preparation(
        choreography_lease,
        recovery_retention_capability,
    )
    if (
        type(action_deadline_monotonic_ns) is not int
        or action_deadline_monotonic_ns != checkpoint.deadline_monotonic_ns
        or checkpoint.observed_monotonic_ns
        >= action_deadline_monotonic_ns
        - POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
    ):
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one call deadline is invalid"
        )
    topology_issuer._require_active_choreography_lease(choreography_lease)


@dataclass(frozen=True, slots=True)
class _Dispatch:
    issuer_reference: weakref.ReferenceType[
        TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer
    ]
    reauthenticate: Callable[[], TrustedTimeHeadAnchorFirstEnrollmentPostcondition]
    close: Callable[[], None]
    revoke: Callable[[], None]
    binding_digest: Callable[[], str]
    configuration_digest: Callable[[], str]


class TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer:
    """Immutable, process-private, single-call sequence-one proof issuer."""

    __slots__ = ("__weakref__", "_capability")

    _capability: _IssuerCapability

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer must be prepared"
        )

    def __setattr__(self, _: str, __: object) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer is immutable"
        )

    def __delattr__(self, _: str) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer is immutable"
        )

    def _dispatch(self) -> _Dispatch:
        if type(self) is not TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer is invalid"
            )
        try:
            capability = self._capability
        except BaseException:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer is invalid"
            ) from None
        return _resolve_trusted_time_post_enrollment_sequence_one_reauthentication_issuer(
            self,
            capability,
        )

    @property
    def issuer_binding_sha256(self) -> str:
        return self._dispatch().binding_digest()

    @property
    def read_only_configuration_sha256(self) -> str:
        return self._dispatch().configuration_digest()

    def reauthenticate_first_enrollment_postcondition(
        self,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
        return self._dispatch().reauthenticate()

    def close(self) -> None:
        self._dispatch().close()

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer cannot be serialized"
        )

    authority_granted = property(_never_authorized)
    operational_control_authorized = property(_never_authorized)
    readiness_authorized = property(_never_authorized)
    release_authorized = property(_never_authorized)
    sequence_2_authorized = property(_never_authorized)
    new_exposure_authorized = property(_never_authorized)
    broker_action_authorized = property(_never_authorized)
    paper_trading_authorized = property(_never_authorized)
    live_trading_authorized = property(_never_authorized)


def _issue_issuer() -> TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer:
    return cast(
        TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
        object.__new__(cast(type[Any], TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer)),
    )


def _poison_issuer(issuer: object) -> None:
    if type(issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer:
        return
    with suppress(BaseException), issuer._lifecycle_lock:
        issuer._poison_locked()


def _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer_with_registry(
    *,
    register_dispatch: Callable[
        [
            TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
            object,
            _Dispatch,
        ],
        None,
    ],
    preparation_validator: Callable[..., _PreparationBinding] = _prepare_exact_binding,
    call_validator: Callable[..., None] = _revalidate_exact_call,
    resource_factory: Callable[..., object] = _create_production_resources,
    reauthentication_runner: Callable[
        [object, _ReauthenticationPhaseGuard],
        TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
    ] = _production_reauthenticate_once,
    monotonic_ns: Callable[[], int] | None = None,
    process_id: Callable[[], int] = os.getpid,
    current_thread: Callable[[], threading.Thread] = threading.current_thread,
) -> Callable[..., TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer]:
    """Private dependency seam for focused hermetic tests."""

    if any(
        not callable(candidate)
        for candidate in (
            register_dispatch,
            preparation_validator,
            call_validator,
            resource_factory,
            reauthentication_runner,
            process_id,
            current_thread,
        )
    ) or (monotonic_ns is not None and not callable(monotonic_ns)):
        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
            "trusted-time sequence-one issuer dependencies are invalid"
        )
    origin_lock = threading.Lock()
    consumed_origin_sha256: set[str] = set()

    def prepare(
        *,
        database_url: str,
        authority: TrustedTimeHeadAnchorAuthority,
        credentials: SupabaseStorageAnchorCredentials,
        verifier: Ed25519TrustedTimeAnchorVerifier,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        action_deadline_monotonic_ns: int,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer:
        exact_origin_established = False
        try:
            configuration = _ReadOnlyConfiguration(
                authority=authority,
                credentials=credentials,
                verifier=verifier,
            )
            exact_database_url = validate_database_url(database_url)
            if (
                runtime_database_project_ref(exact_database_url)
                != authority.runtime_database_project_ref
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
                if binding.origin_sha256 in consumed_origin_sha256:
                    raise ValueError
                consumed_origin_sha256.add(binding.origin_sha256)
            observed = exact_monotonic_ns()
            phase_deadline = (
                action_deadline_monotonic_ns
                - POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
            )
            if (
                type(observed) is not int
                or observed < 0
                or observed >= phase_deadline
                or type(action_deadline_monotonic_ns) is not int
                or action_deadline_monotonic_ns > _MAXIMUM_MONOTONIC_NANOSECONDS
            ):
                raise ValueError
            configuration_sha256 = configuration.configuration_sha256
            binding_digest = _sha256_payload(
                {
                    **binding.payload,
                    "action_deadline_monotonic_ns": action_deadline_monotonic_ns,
                    "artifact_directory": str(artifact_directory),
                    "configuration_sha256": configuration_sha256,
                    "contract_version": (
                        POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION
                    ),
                    "ignored_root": str(ignored_root),
                    "issuer_clock_contract_version": (_ISSUER_CLOCK_BINDING_CONTRACT_VERSION),
                    "origin_pid": owner_pid,
                    "origin_thread_ident": owner_thread.ident,
                    "origin_thread_name": owner_thread.name,
                    "reauthentication_reserve_nanoseconds": (
                        POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
                    ),
                    "runtime_database_project_ref": (authority.runtime_database_project_ref),
                }
            )
            capability = _issue_capability()
            issuer = _issue_issuer()
            object.__setattr__(issuer, "_capability", capability)
            state_lock = threading.Lock()
            state: dict[str, Any] = {
                "binding_digest": binding_digest,
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
                "status": "prepared",
            }

            def require_origin() -> None:
                if (
                    process_id() != state["owner_pid"]
                    or current_thread() is not state["owner_thread"]
                ):
                    raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                        "trusted-time sequence-one issuer crossed its process or thread"
                    )

            def bound_topology_issuer() -> object | None:
                reference = state.get("issuer")
                return reference() if isinstance(reference, weakref.ReferenceType) else None

            def cleanup(*, require_success: bool) -> None:
                owner = state.get("owner")
                if type(owner) is _ResourceOwner:
                    # Close before erasing the topology reference so an
                    # unconfirmed close can still poison the exact issuer.
                    owner.close(require_success=require_success)
                state["resources"] = None
                state["owner"] = None
                state["configuration"] = None
                state["database_url"] = None
                state["issuer"] = None
                state["lease"] = None
                state["monotonic_clock"] = None
                state["recovery"] = None
                tombstone = {
                    "binding_digest": state["binding_digest"],
                    "configuration_digest": state["configuration_digest"],
                    "status": state["status"],
                }
                state.clear()
                state.update(tombstone)

            def reauthenticate() -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
                with state_lock:
                    try:
                        if state["status"] != "prepared":
                            raise (
                                TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                                    "trusted-time sequence-one reauthentication is unavailable"
                                )
                            )
                        require_origin()
                        exact_topology_issuer = bound_topology_issuer()
                        validation_arguments = {
                            "topology_issuer": exact_topology_issuer,
                            "choreography_lease": state["lease"],
                            "recovery_retention_capability": state["recovery"],
                            "action_deadline_monotonic_ns": state["deadline"],
                            "artifact_directory": artifact_directory,
                            "ignored_root": ignored_root,
                        }
                        call_validator(**validation_arguments)
                        guard = _ReauthenticationPhaseGuard(
                            deadline_monotonic_ns=(
                                state["deadline"]
                                - POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
                            ),
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
                        result = reauthentication_runner(resources, guard)
                        if type(result) is not TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
                            raise (
                                TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                                    "trusted-time sequence-one result is invalid"
                                )
                            )
                        result.__post_init__()
                        guard.require_remaining()
                        call_validator(**validation_arguments)
                        state["status"] = "closing"
                        cleanup(require_success=True)
                        state["status"] = "confirmed"
                        return result
                    except TrustedTimePostEnrollmentSequenceOneReauthenticationRejected:
                        if state.get("status") not in {"closed", "confirmed"}:
                            topology = bound_topology_issuer()
                            state["status"] = "closed"
                            cleanup(require_success=False)
                            _poison_issuer(topology)
                        raise
                    except BaseException as error:
                        topology = bound_topology_issuer()
                        state["status"] = "closed"
                        cleanup(require_success=False)
                        _poison_issuer(topology)
                        if not isinstance(error, Exception):
                            raise
                        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                            "trusted-time sequence-one reauthentication is unconfirmed"
                        ) from None

            def close() -> None:
                with state_lock:
                    if state["status"] in {"closed", "confirmed"}:
                        cleanup(require_success=False)
                        return
                    try:
                        require_origin()
                    except TrustedTimePostEnrollmentSequenceOneReauthenticationRejected:
                        return
                    topology = bound_topology_issuer()
                    state["status"] = "closed"
                    cleanup(require_success=False)
                    _poison_issuer(topology)

            def revoke() -> None:
                """Clean an issuer lost between a successful CALL and STORE."""

                with state_lock:
                    if state["status"] in {"closed", "confirmed"}:
                        cleanup(require_success=False)
                        return
                    topology = bound_topology_issuer()
                    state["status"] = "closed"
                    cleanup(require_success=False)
                    _poison_issuer(topology)

            def read_binding_digest() -> str:
                with state_lock:
                    if state["status"] not in {"closed", "confirmed"}:
                        require_origin()
                    value = state["binding_digest"]
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                            "trusted-time sequence-one binding is unavailable"
                        )
                    return cast(str, value)

            def read_configuration_digest() -> str:
                with state_lock:
                    if state["status"] not in {"closed", "confirmed"}:
                        require_origin()
                    value = state["configuration_digest"]
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                            "trusted-time sequence-one configuration is unavailable"
                        )
                    return cast(str, value)

            dispatch = _Dispatch(
                issuer_reference=weakref.ref(issuer),
                reauthenticate=reauthenticate,
                close=close,
                revoke=revoke,
                binding_digest=read_binding_digest,
                configuration_digest=read_configuration_digest,
            )
            register_dispatch(issuer, capability, dispatch)
            return issuer
        except BaseException as error:
            if exact_origin_established:
                _poison_issuer(topology_issuer)
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer preparation failed"
            ) from None

    return prepare


def _build_trusted_time_post_enrollment_sequence_one_reauthentication_registry() -> tuple[
    Callable[
        [TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer, object],
        _Dispatch,
    ],
    Callable[..., Callable[..., TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer]],
]:
    """Seal the dispatch registry and private DI builder in one closure."""

    registry_lock = threading.Lock()
    registry: dict[_IssuerCapability, _Dispatch] = {}
    preparer_implementation = (
        _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer_with_registry
    )

    def register_dispatch(
        issuer: TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
        capability: object,
        dispatch: _Dispatch,
    ) -> None:
        if (
            type(issuer) is not TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer
            or type(capability) is not _IssuerCapability
            or type(dispatch) is not _Dispatch
            or dispatch.issuer_reference() is not issuer
        ):
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer registration is invalid"
            )
        exact_capability = cast(_IssuerCapability, capability)

        def issuer_lost(
            reference: weakref.ReferenceType[
                TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer
            ],
        ) -> None:
            with registry_lock:
                current = registry.get(exact_capability)
                if current is None or current.issuer_reference is not reference:
                    return
                registry.pop(exact_capability, None)
            with suppress(BaseException):
                current.revoke()

        registered_reference = weakref.ref(issuer, issuer_lost)
        registered_dispatch = _Dispatch(
            issuer_reference=registered_reference,
            reauthenticate=dispatch.reauthenticate,
            close=dispatch.close,
            revoke=dispatch.revoke,
            binding_digest=dispatch.binding_digest,
            configuration_digest=dispatch.configuration_digest,
        )
        with registry_lock:
            if exact_capability in registry:
                raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                    "trusted-time sequence-one issuer registration was replayed"
                )
            registry[exact_capability] = registered_dispatch

    def resolve_dispatch(
        issuer: TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
        capability: object,
    ) -> _Dispatch:
        if type(capability) is not _IssuerCapability:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer is unavailable"
            )
        exact_capability = cast(_IssuerCapability, capability)
        with registry_lock:
            dispatch = registry.get(exact_capability)
        if dispatch is None or dispatch.issuer_reference() is not issuer:
            raise TrustedTimePostEnrollmentSequenceOneReauthenticationRejected(
                "trusted-time sequence-one issuer is unavailable"
            )
        return dispatch

    def build_preparer(
        *,
        preparation_validator: Callable[..., _PreparationBinding] = _prepare_exact_binding,
        call_validator: Callable[..., None] = _revalidate_exact_call,
        resource_factory: Callable[..., object] = _create_production_resources,
        reauthentication_runner: Callable[
            [object, _ReauthenticationPhaseGuard],
            TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
        ] = _production_reauthenticate_once,
        monotonic_ns: Callable[[], int] | None = None,
        process_id: Callable[[], int] = os.getpid,
        current_thread: Callable[[], threading.Thread] = threading.current_thread,
    ) -> Callable[..., TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer]:
        return preparer_implementation(
            register_dispatch=register_dispatch,
            preparation_validator=preparation_validator,
            call_validator=call_validator,
            resource_factory=resource_factory,
            reauthentication_runner=reauthentication_runner,
            monotonic_ns=monotonic_ns,
            process_id=process_id,
            current_thread=current_thread,
        )

    return resolve_dispatch, build_preparer


(
    _resolve_trusted_time_post_enrollment_sequence_one_reauthentication_issuer,
    _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer,
) = _build_trusted_time_post_enrollment_sequence_one_reauthentication_registry()
del _build_trusted_time_post_enrollment_sequence_one_reauthentication_registry


prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer = (
    _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer()
)


__all__ = [
    "POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION",
    "POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS",
    "TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer",
    "TrustedTimePostEnrollmentSequenceOneReauthenticationRejected",
    "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer",
]
