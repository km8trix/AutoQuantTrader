"""One-shot read-only reauthentication of a durable ``CLEAN_STOP`` terminal.

The public preparer accepts only an exact database URL and fixed read-only
configuration.  SQL and provider resources are created lazily inside the sole
call.  The issued result is process-local evidence of one bounded observation;
it is not lasting currentness, a durable stop outcome, or shutdown authority.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import sys
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Never, SupportsIndex, cast

from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, event

from apps.trusted_time_supervisor.config import validate_database_url
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
    AuthenticatedTrustedTimeHeadJournalTip,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorProvider,
    TrustedTimeHeadAnchorRecord,
    verify_bounded_clean_stop_terminal_remote_postcondition,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
    trusted_time_first_enrollment_identity_sha256,
)
from packages.persistence.postgres_tls import pinned_verify_full_connect_args
from packages.persistence.trusted_time_head_anchor import (
    PersistedTrustedTimeHeadAnchorIntent,
    PersistedTrustedTimeHeadAnchorReceipt,
    SqlTrustedTimeHeadAnchorRepository,
    TrustedTimeHeadAnchorPersistenceSnapshot,
)

POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
)

_POSTCONDITION_STATUS = "provider_terminal_observed_under_stable_sql_authenticated"
_PHASE_TIMEOUT_NANOSECONDS = 120_000_000_000
_SQL_CONNECT_TIMEOUT_SECONDS = 1
_SQL_STATEMENT_TIMEOUT_MILLISECONDS = 1_000
_SQL_LOCK_TIMEOUT_MILLISECONDS = 500
_SQL_OPERATION_MARGIN_NANOSECONDS = 100_000_000
_REMOTE_OPERATION_MARGIN_NANOSECONDS = 25_000_000
_MAXIMUM_MONOTONIC_NANOSECONDS = (1 << 63) - 1
_ISSUER_CLOCK_CONTRACT_VERSION = "phase6d-post-enrollment-clean-stop-issuer-suspend-aware-clock-v1"


class TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(RuntimeError):
    """The bounded clean-stop terminal observation could not be authenticated."""


def _never_authorized(value: object) -> bool:
    if type(value) is TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        _validate_registered_postcondition(value)
    elif type(value) is TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
        issuer = cast(
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
            value,
        )
        issuer._dispatch().binding_digest()
    else:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop authority subject is invalid"
        )
    return False


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _configuration_projection(
    configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
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
        "contract_version": (POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION),
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
    }


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration:
    """Authority and verifier for a method-narrowed read-only provider observer."""

    authority: TrustedTimeHeadAnchorAuthority
    credentials: SupabaseStorageAnchorCredentials
    verifier: Ed25519TrustedTimeAnchorVerifier

    def __post_init__(self) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration
            or type(self.authority) is not TrustedTimeHeadAnchorAuthority
            or type(self.credentials) is not SupabaseStorageAnchorCredentials
            or type(self.verifier) is not Ed25519TrustedTimeAnchorVerifier
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop read-only configuration is invalid"
            )
        try:
            self.authority.__post_init__()
            self.credentials.__post_init__()
            verifier_public_key_bytes = self.verifier._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except Exception:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop read-only configuration is invalid"
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
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop read-only configuration crosses authority"
            )

    @property
    def configuration_sha256(self) -> str:
        self.__post_init__()
        return _sha256_payload(_configuration_projection(self))

    def __repr__(self) -> str:
        return (
            "TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration("
            f"authority={self.authority!r}, credentials=<redacted>, "
            f"verifier={self.verifier!r})"
        )


def _authority_values(authority: TrustedTimeHeadAnchorAuthority) -> tuple[object, ...]:
    return (
        authority.anchor_authority_sha256,
        authority.deployment_identity_sha256,
        authority.host_id,
        authority.source_authority_sha256,
        authority.runtime_database_project_ref,
        authority.runtime_database_identity_sha256,
        authority.anchor_project_ref,
        authority.anchor_project_url,
        authority.anchor_project_identity_sha256,
        authority.bucket_name,
        authority.principal_id,
        authority.signing_key_id,
        authority.signing_public_key_sha256,
        authority.signing_public_key_bytes,
        authority.checkpoint_interval_seconds,
        authority.stale_after_seconds,
    )


def _credential_values(credentials: SupabaseStorageAnchorCredentials) -> tuple[str, ...]:
    return (
        credentials.project_url,
        credentials.publishable_key,
        credentials.principal_id,
        credentials.anchor_project_identity_sha256,
        credentials.email,
        credentials.password,
    )


def _verifier_values(verifier: Ed25519TrustedTimeAnchorVerifier) -> tuple[object, ...]:
    public_key_bytes = verifier._public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        verifier.signing_key_id,
        verifier.signing_public_key_sha256,
        verifier._public_key,
        public_key_bytes,
    )


@dataclass(frozen=True, slots=True)
class _ConfigurationBinding:
    original_configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration
    original_authority: TrustedTimeHeadAnchorAuthority
    original_credentials: SupabaseStorageAnchorCredentials
    original_verifier: Ed25519TrustedTimeAnchorVerifier
    authority_values: tuple[object, ...]
    credential_values: tuple[str, ...] = field(repr=False)
    verifier_values: tuple[object, ...]
    private_configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration
    private_nested_identities: tuple[object, object, object] = field(repr=False)
    private_verifier_values: tuple[object, ...] = field(repr=False)
    public_configuration_sha256: str

    def revalidate(self) -> None:
        configuration = self.original_configuration
        if (
            type(configuration) is not TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration
            or configuration.authority is not self.original_authority
            or configuration.credentials is not self.original_credentials
            or configuration.verifier is not self.original_verifier
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop read-only configuration identity drifted"
            )
        configuration.__post_init__()
        if (
            _authority_values(self.original_authority) != self.authority_values
            or _credential_values(self.original_credentials) != self.credential_values
            or _verifier_values(self.original_verifier) != self.verifier_values
            or configuration.configuration_sha256 != self.public_configuration_sha256
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop read-only configuration drifted"
            )
        private_configuration = self.private_configuration
        private_authority, private_credentials, private_verifier = self.private_nested_identities
        if (
            type(private_configuration)
            is not TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration
            or private_configuration.authority is not private_authority
            or private_configuration.credentials is not private_credentials
            or private_configuration.verifier is not private_verifier
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop private configuration identity drifted"
            )
        private_configuration.__post_init__()
        if (
            _authority_values(private_configuration.authority) != self.authority_values
            or _credential_values(private_configuration.credentials) != self.credential_values
            or _verifier_values(private_configuration.verifier) != self.private_verifier_values
            or private_configuration.configuration_sha256 != self.public_configuration_sha256
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop private configuration drifted"
            )


def _capture_configuration_binding(
    configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
) -> _ConfigurationBinding:
    configuration.__post_init__()
    authority = configuration.authority
    credentials = configuration.credentials
    verifier = configuration.verifier
    authority_values = _authority_values(authority)
    credential_values = _credential_values(credentials)
    verifier_values = _verifier_values(verifier)
    private_authority = TrustedTimeHeadAnchorAuthority(
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        host_id=authority.host_id,
        source_authority_sha256=authority.source_authority_sha256,
        runtime_database_project_ref=authority.runtime_database_project_ref,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
        anchor_project_ref=authority.anchor_project_ref,
        anchor_project_url=authority.anchor_project_url,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        bucket_name=authority.bucket_name,
        principal_id=authority.principal_id,
        signing_key_id=authority.signing_key_id,
        signing_public_key_sha256=authority.signing_public_key_sha256,
        signing_public_key_bytes=authority.signing_public_key_bytes,
        checkpoint_interval_seconds=authority.checkpoint_interval_seconds,
        stale_after_seconds=authority.stale_after_seconds,
    )
    private_credentials = SupabaseStorageAnchorCredentials(
        project_url=credentials.project_url,
        publishable_key=credentials.publishable_key,
        principal_id=credentials.principal_id,
        anchor_project_identity_sha256=credentials.anchor_project_identity_sha256,
        email=credentials.email,
        password=credentials.password,
    )
    verifier_public_key_bytes = cast(bytes, verifier_values[3])
    private_verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
        signing_key_id=verifier.signing_key_id,
        expected_signing_public_key_sha256=verifier.signing_public_key_sha256,
        public_key_bytes=verifier_public_key_bytes,
    )
    private_configuration = TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration(
        authority=private_authority,
        credentials=private_credentials,
        verifier=private_verifier,
    )
    public_configuration_sha256 = private_configuration.configuration_sha256
    binding = _ConfigurationBinding(
        original_configuration=configuration,
        original_authority=authority,
        original_credentials=credentials,
        original_verifier=verifier,
        authority_values=authority_values,
        credential_values=credential_values,
        verifier_values=verifier_values,
        private_configuration=private_configuration,
        private_nested_identities=(
            private_authority,
            private_credentials,
            private_verifier,
        ),
        private_verifier_values=_verifier_values(private_verifier),
        public_configuration_sha256=public_configuration_sha256,
    )
    binding.revalidate()
    return binding


class _DarwinMachTimebaseInfo(ctypes.Structure):
    _fields_ = (("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32))


def _build_suspend_aware_monotonic_clock(
    *,
    platform_name: object,
    clock_gettime_ns: object,
    clock_boottime: object,
    darwin_library_loader: object,
) -> Callable[[], int]:
    """Capture one native suspend-aware monotonic clock for this process."""

    def unavailable() -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop suspend-aware clock is unavailable"
        ) from None

    def validate(observed: object) -> int:
        if type(observed) is not int or observed < 0 or observed > _MAXIMUM_MONOTONIC_NANOSECONDS:
            unavailable()
        return observed

    if platform_name == "linux" and callable(clock_gettime_ns) and type(clock_boottime) is int:
        captured_clock_gettime_ns = cast(Callable[[int], object], clock_gettime_ns)
        captured_clock_boottime = clock_boottime

        def linux_clock() -> int:
            try:
                observed = captured_clock_gettime_ns(captured_clock_boottime)
            except Exception:
                unavailable()
            return validate(observed)

        return linux_clock

    if platform_name == "darwin" and callable(darwin_library_loader):
        try:
            library = cast(Any, cast(Callable[[object], object], darwin_library_loader)(None))
            continuous_time = cast(Any, library.mach_continuous_time)
            continuous_time.argtypes = []
            continuous_time.restype = ctypes.c_uint64
            timebase_info = cast(Any, library.mach_timebase_info)
            timebase_info.argtypes = [ctypes.POINTER(_DarwinMachTimebaseInfo)]
            timebase_info.restype = ctypes.c_int
            timebase = _DarwinMachTimebaseInfo()
            if timebase_info(ctypes.byref(timebase)) != 0:
                raise ValueError
            numerator = int(timebase.numer)
            denominator = int(timebase.denom)
            if numerator <= 0 or denominator <= 0:
                raise ValueError
        except Exception:
            return unavailable
        captured_continuous_time = cast(Callable[[], object], continuous_time)

        def darwin_clock() -> int:
            try:
                ticks = captured_continuous_time()
                if type(ticks) is not int:
                    unavailable()
                observed = ticks * numerator // denominator
            except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
                raise
            except Exception:
                unavailable()
            return validate(observed)

        return darwin_clock

    return unavailable


_suspend_aware_monotonic_ns = _build_suspend_aware_monotonic_clock(
    platform_name=sys.platform,
    clock_gettime_ns=getattr(time, "clock_gettime_ns", None),
    clock_boottime=getattr(time, "CLOCK_BOOTTIME", None),
    darwin_library_loader=ctypes.CDLL,
)


@dataclass(frozen=True, slots=True)
class _SqlProjection:
    receipt: PersistedTrustedTimeHeadAnchorReceipt
    intent: PersistedTrustedTimeHeadAnchorIntent
    record: TrustedTimeHeadAnchorRecord
    journal_tip: AuthenticatedTrustedTimeHeadJournalTip
    anchor_sequence: int
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    predecessor_anchor_sha256: str
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    receipt_semantic_sha256: str
    receipt_observed_at_utc: datetime


def _capture_sql_projection(
    snapshot: object,
    *,
    authority: TrustedTimeHeadAnchorAuthority,
) -> _SqlProjection:
    """Validate and capture one exact repository-issued full replay."""

    try:
        if type(snapshot) is not TrustedTimeHeadAnchorPersistenceSnapshot:
            raise ValueError
        exact = snapshot
        receipt = exact.confirmed_anchor_receipt
        tip = exact.authenticated_journal_tip
        if (
            type(receipt) is not PersistedTrustedTimeHeadAnchorReceipt
            or type(tip) is not AuthenticatedTrustedTimeHeadJournalTip
        ):
            raise ValueError
        receipt.__post_init__()
        tip.__post_init__()
        intent = receipt.intent
        record = intent.record
        if (
            type(intent) is not PersistedTrustedTimeHeadAnchorIntent
            or type(record) is not TrustedTimeHeadAnchorRecord
        ):
            raise ValueError
        intent.__post_init__()
        record.__post_init__()
        terminal_ordinal = tip.confirmed_anchor_local_transition_ordinal
        if (
            exact.complete_replay is not True
            or exact.pending_intent is not None
            or type(exact.confirmed_anchor_count) is not int
            or type(exact.local_transition_count) is not int
            or type(terminal_ordinal) is not int
            or record.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
            or record.anchor_sequence < 3
            or exact.confirmed_anchor_count != record.anchor_sequence
            or exact.local_transition_count < record.anchor_sequence
            or terminal_ordinal != exact.local_transition_count
            or type(record.previous_anchor_sha256) is not str
            or not _is_sha256(record.previous_anchor_sha256)
            or tip.confirmed_anchor_count != record.anchor_sequence
            or tip.confirmed_anchor_tip != record
            or tip.local_transition_count != exact.local_transition_count
            or tip.current_local_host_head_sha256 != exact.current_host_head_sha256
            or exact.current_host_head_sha256 != record.current_host_head_sha256
            or receipt.readback_bytes_sha256 != record.byte_sha256
            or record.anchor_authority_sha256 != authority.anchor_authority_sha256
            or record.deployment_identity_sha256 != authority.deployment_identity_sha256
            or record.runtime_database_identity_sha256 != authority.runtime_database_identity_sha256
            or record.anchor_project_identity_sha256 != authority.anchor_project_identity_sha256
            or record.anchor_project_ref != authority.anchor_project_ref
            or record.bucket_name != authority.bucket_name
            or record.principal_id != authority.principal_id
            or record.host_id != authority.host_id
            or record.source_authority_sha256 != authority.source_authority_sha256
            or record.signing_key_id != authority.signing_key_id
            or record.signing_public_key_sha256 != authority.signing_public_key_sha256
            or record.checkpoint_interval_seconds
            != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise ValueError
        return _SqlProjection(
            receipt=receipt,
            intent=intent,
            record=record,
            journal_tip=tip,
            anchor_sequence=record.anchor_sequence,
            confirmed_anchor_count=exact.confirmed_anchor_count,
            local_transition_count=exact.local_transition_count,
            confirmed_anchor_local_transition_ordinal=terminal_ordinal,
            predecessor_anchor_sha256=record.previous_anchor_sha256,
            current_host_head_sha256=record.current_host_head_sha256,
            current_anchor_sha256=record.byte_sha256,
            current_anchor_semantic_sha256=record.semantic_sha256,
            anchor_intent_semantic_sha256=intent.semantic_sha256,
            candidate_remote_readback_sha256=receipt.readback_bytes_sha256,
            receipt_semantic_sha256=receipt.semantic_sha256,
            receipt_observed_at_utc=receipt.observed_at_utc,
        )
    except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop SQL terminal is unconfirmed"
        ) from None


@dataclass(frozen=True, slots=True)
class _VerifiedObservation:
    projection: _SqlProjection
    remote_observation_sha256: str
    observation_started_monotonic_ns: int
    observation_completed_monotonic_ns: int
    deadline_monotonic_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.projection) is not _SqlProjection
            or not _is_sha256(self.remote_observation_sha256)
            or type(self.observation_started_monotonic_ns) is not int
            or type(self.observation_completed_monotonic_ns) is not int
            or type(self.deadline_monotonic_ns) is not int
            or not 0
            <= self.observation_started_monotonic_ns
            <= self.observation_completed_monotonic_ns
            < self.deadline_monotonic_ns
            <= _MAXIMUM_MONOTONIC_NANOSECONDS
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop verified observation is invalid"
            )


class _PostconditionCapability:
    __slots__ = ()

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop postcondition capability is unavailable"
        )


def _postcondition_values(
    value: TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
) -> tuple[object, ...]:
    return (
        value.anchor_sequence,
        value.checkpoint_reason,
        value.confirmed_anchor_count,
        value.local_transition_count,
        value.confirmed_anchor_local_transition_ordinal,
        value.remote_object_count,
        value.predecessor_anchor_sha256,
        value.current_host_head_sha256,
        value.current_anchor_sha256,
        value.current_anchor_semantic_sha256,
        value.anchor_intent_semantic_sha256,
        value.candidate_remote_readback_sha256,
        value.receipt_semantic_sha256,
        value.receipt_observed_at_utc,
        value.remote_observation_sha256,
        value.anchor_authority_sha256,
        value.deployment_identity_sha256,
        value.runtime_database_identity_sha256,
        value.anchor_project_identity_sha256,
        value.source_authority_sha256,
        value.signing_public_key_sha256,
        value.host_identity_sha256,
        value.principal_identity_sha256,
        value.bucket_identity_sha256,
        value.observation_started_monotonic_ns,
        value.observation_completed_monotonic_ns,
        value.deadline_monotonic_ns,
        value.issuer_binding_sha256,
        value.read_only_configuration_sha256,
    )


def _postcondition_payload(values: tuple[object, ...]) -> dict[str, object]:
    (
        anchor_sequence,
        checkpoint_reason,
        confirmed_anchor_count,
        local_transition_count,
        terminal_ordinal,
        remote_object_count,
        predecessor_anchor_sha256,
        current_host_head_sha256,
        current_anchor_sha256,
        current_anchor_semantic_sha256,
        anchor_intent_semantic_sha256,
        candidate_remote_readback_sha256,
        receipt_semantic_sha256,
        receipt_observed_at_utc,
        remote_observation_sha256,
        anchor_authority_sha256,
        deployment_identity_sha256,
        runtime_database_identity_sha256,
        anchor_project_identity_sha256,
        source_authority_sha256,
        signing_public_key_sha256,
        host_identity_sha256,
        principal_identity_sha256,
        bucket_identity_sha256,
        observation_started_monotonic_ns,
        observation_completed_monotonic_ns,
        deadline_monotonic_ns,
        issuer_binding_sha256,
        read_only_configuration_sha256,
    ) = values
    if (
        type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason
        or type(receipt_observed_at_utc) is not datetime
    ):
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop postcondition payload is invalid"
        )
    return {
        "anchor_authority_sha256": anchor_authority_sha256,
        "anchor_intent_semantic_sha256": anchor_intent_semantic_sha256,
        "anchor_project_identity_sha256": anchor_project_identity_sha256,
        "anchor_sequence": anchor_sequence,
        "bucket_identity_sha256": bucket_identity_sha256,
        "candidate_remote_readback_sha256": candidate_remote_readback_sha256,
        "checkpoint_reason": checkpoint_reason.value,
        "confirmed_anchor_count": confirmed_anchor_count,
        "confirmed_anchor_local_transition_ordinal": terminal_ordinal,
        "contract_version": (POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION),
        "current_anchor_semantic_sha256": current_anchor_semantic_sha256,
        "current_anchor_sha256": current_anchor_sha256,
        "current_host_head_sha256": current_host_head_sha256,
        "deadline_monotonic_ns": deadline_monotonic_ns,
        "deployment_identity_sha256": deployment_identity_sha256,
        "host_identity_sha256": host_identity_sha256,
        "issuer_binding_sha256": issuer_binding_sha256,
        "local_transition_count": local_transition_count,
        "observation_completed_monotonic_ns": observation_completed_monotonic_ns,
        "observation_started_monotonic_ns": observation_started_monotonic_ns,
        "predecessor_anchor_sha256": predecessor_anchor_sha256,
        "principal_identity_sha256": principal_identity_sha256,
        "read_only_configuration_sha256": read_only_configuration_sha256,
        "receipt_observed_at_utc": _utc_text(receipt_observed_at_utc),
        "receipt_semantic_sha256": receipt_semantic_sha256,
        "remote_object_count": remote_object_count,
        "remote_observation_sha256": remote_observation_sha256,
        "runtime_database_identity_sha256": runtime_database_identity_sha256,
        "signing_public_key_sha256": signing_public_key_sha256,
        "source_authority_sha256": source_authority_sha256,
        "status": _POSTCONDITION_STATUS,
    }


def _validate_postcondition_values(values: tuple[object, ...]) -> None:
    payload = _postcondition_payload(values)
    anchor_sequence = payload["anchor_sequence"]
    confirmed_anchor_count = payload["confirmed_anchor_count"]
    local_transition_count = payload["local_transition_count"]
    terminal_ordinal = payload["confirmed_anchor_local_transition_ordinal"]
    remote_object_count = payload["remote_object_count"]
    if (
        type(anchor_sequence) is not int
        or anchor_sequence < 3
        or confirmed_anchor_count != anchor_sequence
        or remote_object_count != anchor_sequence
        or type(local_transition_count) is not int
        or type(terminal_ordinal) is not int
        or terminal_ordinal != local_transition_count
        or local_transition_count < anchor_sequence
        or values[1] is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        or any(
            not _is_sha256(item)
            for item in (
                *values[6:13],
                values[14],
                *values[15:24],
                values[27],
                values[28],
            )
        )
        or values[11] != values[8]
    ):
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop postcondition values are invalid"
        )
    receipt_instant = values[13]
    if (
        type(receipt_instant) is not datetime
        or receipt_instant.tzinfo is None
        or receipt_instant.utcoffset() != UTC.utcoffset(receipt_instant)
        or any(type(item) is not int for item in values[24:27])
        or not 0 <= cast(int, values[24]) <= cast(int, values[25]) < cast(int, values[26])
    ):
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop postcondition chronology is invalid"
        )


_PostconditionRegistration = tuple[
    weakref.ReferenceType["TrustedTimePostEnrollmentCleanStopTerminalPostcondition"],
    _PostconditionCapability,
    int,
    threading.Thread,
    tuple[object, ...],
    str,
    weakref.ReferenceType["TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer"],
    object | None,
    bool,
]


@dataclass(frozen=True, slots=True)
class _ConsumedPostconditionRegistrySnapshot:
    """Immutable values captured by the one-shot postcondition registry."""

    values: tuple[object, ...]
    semantic_sha256: str
    issuer_identity: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    bridge_identity: object

    def __post_init__(self) -> None:
        if (
            type(self.values) is not tuple
            or len(self.values) != 29
            or not _is_sha256(self.semantic_sha256)
            or type(self.issuer_identity)
            is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            or self.bridge_identity is None
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop consumed postcondition snapshot is invalid"
            )


_POSTCONDITION_REGISTRY_ORIGIN_PID = os.getpid()
_POSTCONDITION_REGISTRY_LOCK = threading.Lock()
_POSTCONDITION_REGISTRY: dict[int, _PostconditionRegistration] = {}


def _validate_registered_postcondition(value: object) -> None:
    try:
        if (
            os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID
            or type(value) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
        ):
            raise ValueError
        exact = value
        values = _postcondition_values(exact)
        _validate_postcondition_values(values)
        semantic_sha256 = object.__getattribute__(exact, "_semantic_sha256")
        if not _is_sha256(semantic_sha256) or semantic_sha256 != _sha256_payload(
            _postcondition_payload(values)
        ):
            raise ValueError
        with _POSTCONDITION_REGISTRY_LOCK:
            registration = _POSTCONDITION_REGISTRY.get(id(exact))
        if (
            registration is None
            or registration[0]() is not exact
            or registration[2] != os.getpid()
            or registration[3] is not threading.current_thread()
            or registration[4] != values
            or registration[5] != semantic_sha256
            or type(registration[8]) is not bool
            or (registration[8] and registration[7] is None)
            or (not registration[8] and registration[7] is not None)
        ):
            raise ValueError
    except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition is invalid"
        ) from None


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False, eq=False)
class TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
    """Sealed evidence of one provider-terminal observation under stable SQL."""

    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    remote_object_count: int
    predecessor_anchor_sha256: str
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    receipt_semantic_sha256: str
    receipt_observed_at_utc: datetime
    remote_observation_sha256: str
    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    source_authority_sha256: str
    signing_public_key_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    bucket_identity_sha256: str
    observation_started_monotonic_ns: int
    observation_completed_monotonic_ns: int
    deadline_monotonic_ns: int
    issuer_binding_sha256: str
    read_only_configuration_sha256: str
    _semantic_sha256: str

    def __new__(cls) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition must be issued"
        )

    def __post_init__(self) -> None:
        _validate_registered_postcondition(self)

    @property
    def contract_version(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION

    @property
    def status(self) -> str:
        self.__post_init__()
        return _POSTCONDITION_STATUS

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return self._semantic_sha256

    @property
    def provider_terminal_observed_under_stable_sql_authenticated(self) -> bool:
        self.__post_init__()
        return True

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition cannot be serialized"
        )

    authority_granted = property(_never_authorized)
    database_secret_disclosed = property(_never_authorized)
    provider_terminal_currentness_authenticated = property(_never_authorized)
    no_new_record_authenticated = property(_never_authorized)
    durability_authenticated = property(_never_authorized)
    durable_stop_outcome_authenticated = property(_never_authorized)
    slot_authorized = property(_never_authorized)
    admission_authorized = property(_never_authorized)
    effect_authorized = property(_never_authorized)
    active_controller_authorized = property(_never_authorized)
    claim_retention_authorized = property(_never_authorized)
    clean_stop_authorized = property(_never_authorized)
    clean_stop_outcome_retention_authorized = property(_never_authorized)
    confirmed_start_outcome_authenticated = property(_never_authorized)
    container_removal_authorized = property(_never_authorized)
    controller_execution_authorized = property(_never_authorized)
    current_topology_authenticated = property(_never_authorized)
    decision_authenticated = property(_never_authorized)
    execution_admission_authorized = property(_never_authorized)
    execution_attempt_reservation_authorized = property(_never_authorized)
    freshness_authenticated = property(_never_authorized)
    graceful_stop_authorized = property(_never_authorized)
    network_removal_authorized = property(_never_authorized)
    operator_attestation_authenticated = property(_never_authorized)
    outcome_retention_authorized = property(_never_authorized)
    persistent_start_authorized = property(_never_authorized)
    persistent_topology_authenticated = property(_never_authorized)
    qualified = property(_never_authorized)
    rearm_authorized = property(_never_authorized)
    release_authorized = property(_never_authorized)
    retry_authorized = property(_never_authorized)
    runtime_start_authorized = property(_never_authorized)
    sequence_2_authorized = property(_never_authorized)
    shutdown_locator_authenticated = property(_never_authorized)
    shutdown_outcome_retention_authorized = property(_never_authorized)
    single_use_authenticated = property(_never_authorized)
    source_start_authorized = property(_never_authorized)
    source_stop_authorized = property(_never_authorized)
    start_execution_attempt_authenticated = property(_never_authorized)
    stop_attempt_reservation_authorized = property(_never_authorized)
    stop_decision_authenticated = property(_never_authorized)
    stop_execution_authorized = property(_never_authorized)
    success_outcome_retention_authorized = property(_never_authorized)
    supervisor_signal_authorized = property(_never_authorized)
    supervisor_start_authorized = property(_never_authorized)
    supervisor_stop_authorized = property(_never_authorized)
    target_authenticated = property(_never_authorized)
    topology_mutation_authorized = property(_never_authorized)
    volume_removal_authorized = property(_never_authorized)
    currentness_qualified = property(_never_authorized)
    freshness_qualified = property(_never_authorized)
    durable = property(_never_authorized)
    no_new_record_success = property(_never_authorized)
    stop_outcome_retained = property(_never_authorized)
    stop_attempt_slot_reserved = property(_never_authorized)
    stop_admission_qualified = property(_never_authorized)
    signal_authorized = property(_never_authorized)
    shutdown_authorized = property(_never_authorized)
    teardown_authorized = property(_never_authorized)
    watchdog_authorized = property(_never_authorized)
    operational_control_authorized = property(_never_authorized)
    readiness_authorized = property(_never_authorized)
    arming_authorized = property(_never_authorized)
    new_exposure_authorized = property(_never_authorized)
    broker_action_authorized = property(_never_authorized)
    automatic_rearm_authorized = property(_never_authorized)
    automatic_resume_authorized = property(_never_authorized)
    alert_delivery_authorized = property(_never_authorized)
    exposure_authorized = property(_never_authorized)
    paper_trading_authorized = property(_never_authorized)
    live_trading_authorized = property(_never_authorized)


def _issue_postcondition(
    *,
    issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    issuer_capability: object,
    observation: _VerifiedObservation,
    authority: TrustedTimeHeadAnchorAuthority,
    issuer_binding_sha256: str,
    configuration_sha256: str,
    owner_pid: int,
    owner_thread: threading.Thread,
) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
    if (
        type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
        or type(issuer_capability) is not _PostconditionCapability
        or type(observation) is not _VerifiedObservation
        or type(authority) is not TrustedTimeHeadAnchorAuthority
        or not _is_sha256(issuer_binding_sha256)
        or not _is_sha256(configuration_sha256)
        or owner_pid != os.getpid()
        or owner_thread is not threading.current_thread()
    ):
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition issuance is invalid"
        )
    observation.__post_init__()
    dispatch = _resolve_issuer_dispatch(issuer, issuer_capability)
    dispatch.consume_issuance(observation)
    projection = observation.projection
    result = cast(
        TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
        object.__new__(cast(type[Any], TrustedTimePostEnrollmentCleanStopTerminalPostcondition)),
    )
    fields = {
        "anchor_sequence": projection.anchor_sequence,
        "checkpoint_reason": projection.record.checkpoint_reason,
        "confirmed_anchor_count": projection.confirmed_anchor_count,
        "local_transition_count": projection.local_transition_count,
        "confirmed_anchor_local_transition_ordinal": (
            projection.confirmed_anchor_local_transition_ordinal
        ),
        "remote_object_count": projection.anchor_sequence,
        "predecessor_anchor_sha256": projection.predecessor_anchor_sha256,
        "current_host_head_sha256": projection.current_host_head_sha256,
        "current_anchor_sha256": projection.current_anchor_sha256,
        "current_anchor_semantic_sha256": projection.current_anchor_semantic_sha256,
        "anchor_intent_semantic_sha256": projection.anchor_intent_semantic_sha256,
        "candidate_remote_readback_sha256": projection.candidate_remote_readback_sha256,
        "receipt_semantic_sha256": projection.receipt_semantic_sha256,
        "receipt_observed_at_utc": projection.receipt_observed_at_utc,
        "remote_observation_sha256": observation.remote_observation_sha256,
        "anchor_authority_sha256": authority.anchor_authority_sha256,
        "deployment_identity_sha256": authority.deployment_identity_sha256,
        "runtime_database_identity_sha256": authority.runtime_database_identity_sha256,
        "anchor_project_identity_sha256": authority.anchor_project_identity_sha256,
        "source_authority_sha256": authority.source_authority_sha256,
        "signing_public_key_sha256": authority.signing_public_key_sha256,
        "host_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="host", value=authority.host_id
        ),
        "principal_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="principal", value=authority.principal_id
        ),
        "bucket_identity_sha256": trusted_time_first_enrollment_identity_sha256(
            kind="bucket", value=authority.bucket_name
        ),
        "observation_started_monotonic_ns": observation.observation_started_monotonic_ns,
        "observation_completed_monotonic_ns": observation.observation_completed_monotonic_ns,
        "deadline_monotonic_ns": observation.deadline_monotonic_ns,
        "issuer_binding_sha256": issuer_binding_sha256,
        "read_only_configuration_sha256": configuration_sha256,
    }
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    values = _postcondition_values(result)
    _validate_postcondition_values(values)
    semantic_sha256 = _sha256_payload(_postcondition_payload(values))
    object.__setattr__(result, "_semantic_sha256", semantic_sha256)
    result_id = id(result)

    def result_lost(
        reference: weakref.ReferenceType[TrustedTimePostEnrollmentCleanStopTerminalPostcondition],
    ) -> None:
        if os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID:
            return
        with _POSTCONDITION_REGISTRY_LOCK:
            current = _POSTCONDITION_REGISTRY.get(result_id)
            if current is not None and current[0] is reference:
                _POSTCONDITION_REGISTRY.pop(result_id, None)

    result_reference = weakref.ref(result, result_lost)
    registration: _PostconditionRegistration = (
        result_reference,
        cast(_PostconditionCapability, issuer_capability),
        owner_pid,
        owner_thread,
        values,
        semantic_sha256,
        weakref.ref(issuer),
        None,
        False,
    )
    if os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition issuance is invalid"
        )
    with _POSTCONDITION_REGISTRY_LOCK:
        if result_id in _POSTCONDITION_REGISTRY:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop terminal postcondition registration was replayed"
            )
        _POSTCONDITION_REGISTRY[result_id] = registration
    try:
        result.__post_init__()
    except BaseException:
        _revoke_issued_postcondition(
            result,
            issuer_capability=issuer_capability,
        )
        raise
    return result


def _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
    value: object,
    *,
    issuer: object,
    bridge_identity: object,
) -> _ConsumedPostconditionRegistrySnapshot:
    """Burn one exact issued observation into one exact host bridge identity.

    The registry entry is removed before the detailed seal checks.  Any
    mismatch therefore consumes the observation rather than leaving it
    available for a second composition attempt.  A successful observation
    remains registered and inspectable, but its exact bridge identity cannot
    be changed or replayed.
    """

    try:
        if (
            os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID
            or type(value) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
        ):
            raise ValueError
        exact = value
        with _POSTCONDITION_REGISTRY_LOCK:
            registration = _POSTCONDITION_REGISTRY.pop(id(exact), None)
        if registration is None:
            raise ValueError
        if (
            type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            or bridge_identity is None
        ):
            raise ValueError
        exact_issuer = cast(
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
            issuer,
        )
        values = _postcondition_values(exact)
        _validate_postcondition_values(values)
        semantic_sha256 = object.__getattribute__(exact, "_semantic_sha256")
        try:
            issuer_capability = object.__getattribute__(exact_issuer, "_capability")
        except Exception:
            raise ValueError from None
        if (
            registration[0]() is not exact
            or registration[1] is not issuer_capability
            or registration[2] != os.getpid()
            or registration[3] is not threading.current_thread()
            or registration[4] != values
            or registration[5] != semantic_sha256
            or not _is_sha256(semantic_sha256)
            or semantic_sha256 != _sha256_payload(_postcondition_payload(values))
            or registration[6]() is not exact_issuer
            or registration[7] is not None
            or registration[8]
        ):
            raise ValueError
        consumed = _ConsumedPostconditionRegistrySnapshot(
            values=registration[4],
            semantic_sha256=registration[5],
            issuer_identity=exact_issuer,
            bridge_identity=bridge_identity,
        )
        consumed.__post_init__()
        if os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID:
            raise ValueError
        with _POSTCONDITION_REGISTRY_LOCK:
            if id(exact) in _POSTCONDITION_REGISTRY:
                raise ValueError
            _POSTCONDITION_REGISTRY[id(exact)] = (
                *registration[:7],
                bridge_identity,
                True,
            )
        return consumed
    except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition cannot be consumed"
        ) from None


def _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
    value: object,
    *,
    issuer: object,
    bridge_identity: object,
) -> _ConsumedPostconditionRegistrySnapshot:
    """Revalidate one successful exact issuer/bridge consumption without mutation."""

    try:
        if (
            os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID
            or type(value) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
            or type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            or bridge_identity is None
        ):
            raise ValueError
        exact = value
        exact_issuer = cast(
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
            issuer,
        )
        with _POSTCONDITION_REGISTRY_LOCK:
            registration = _POSTCONDITION_REGISTRY.get(id(exact))
        if (
            registration is None
            or registration[0]() is not exact
            or registration[2] != os.getpid()
            or registration[3] is not threading.current_thread()
            or registration[6]() is not exact_issuer
            or registration[7] is not bridge_identity
            or registration[8] is not True
        ):
            raise ValueError
        values = _postcondition_values(exact)
        _validate_postcondition_values(values)
        semantic_sha256 = object.__getattribute__(exact, "_semantic_sha256")
        issuer_capability = object.__getattribute__(exact_issuer, "_capability")
        if (
            registration[1] is not issuer_capability
            or registration[4] != values
            or registration[5] != semantic_sha256
            or not _is_sha256(semantic_sha256)
            or semantic_sha256 != _sha256_payload(_postcondition_payload(values))
        ):
            raise ValueError
        consumed = _ConsumedPostconditionRegistrySnapshot(
            values=registration[4],
            semantic_sha256=registration[5],
            issuer_identity=exact_issuer,
            bridge_identity=bridge_identity,
        )
        consumed.__post_init__()
        return consumed
    except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal postcondition consumption is invalid"
        ) from None


def _revoke_issued_postcondition(
    value: object,
    *,
    issuer_capability: object,
) -> None:
    if (
        os.getpid() != _POSTCONDITION_REGISTRY_ORIGIN_PID
        or type(value) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    ):
        return
    with _POSTCONDITION_REGISTRY_LOCK:
        registration = _POSTCONDITION_REGISTRY.get(id(value))
        if (
            registration is not None
            and registration[0]() is value
            and registration[1] is issuer_capability
        ):
            _POSTCONDITION_REGISTRY.pop(id(value), None)


class _ResourceOwner:
    """Register cleanup before any newly constructed resource can escape."""

    __slots__ = ("_closed", "_closers", "_lock")

    def __init__(self) -> None:
        self._closed = False
        self._closers: list[tuple[object | None, Callable[[], None]]] = []
        self._lock = threading.Lock()

    def register(self, closer: Callable[[], None]) -> None:
        self._register(resource=None, closer=closer)

    def register_owned(self, resource: object, closer: Callable[[], None]) -> None:
        if resource is None:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop resource cleanup is invalid"
            )
        self._register(resource=resource, closer=closer)

    def _register(self, *, resource: object | None, closer: Callable[[], None]) -> None:
        if not callable(closer):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop resource cleanup is invalid"
            )
        with self._lock:
            if self._closed:
                with suppress(Exception):
                    closer()
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop resources are closed"
                )
            self._closers.append((resource, closer))

    def _owns_or_is_closed(self, resource: object) -> bool:
        with self._lock:
            return self._closed or any(item is resource for item, _ in self._closers)

    def close(self, *, require_success: bool) -> None:
        failures = False
        first_async_error: BaseException | None = None
        with self._lock:
            if self._closed:
                return
            self._closed = True
            closers = tuple(reversed(self._closers))
            self._closers.clear()
        for _, closer in closers:
            try:
                closer()
            except BaseException as error:
                if isinstance(error, Exception):
                    failures = True
                elif first_async_error is None:
                    first_async_error = error
        if first_async_error is not None:
            raise first_async_error
        if failures and require_success:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop resource cleanup is unconfirmed"
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
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop resource is unavailable"
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
        "_started_monotonic_ns",
    )

    def __init__(
        self,
        *,
        started_monotonic_ns: int,
        deadline_monotonic_ns: int,
        clock: Callable[[], int],
        owner_pid: int,
        owner_thread: threading.Thread,
    ) -> None:
        self._clock = clock
        self._deadline_monotonic_ns = deadline_monotonic_ns
        self._owner_pid = owner_pid
        self._owner_thread = owner_thread
        self._started_monotonic_ns = started_monotonic_ns
        self._last_observed_monotonic_ns = started_monotonic_ns
        self.require_remaining()

    @property
    def started_monotonic_ns(self) -> int:
        return self._started_monotonic_ns

    @property
    def deadline_monotonic_ns(self) -> int:
        return self._deadline_monotonic_ns

    def observe(self) -> int:
        if os.getpid() != self._owner_pid or threading.current_thread() is not self._owner_thread:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop verification crossed its process or thread"
            )
        try:
            observed = self._clock()
        except Exception:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop deadline clock failed"
            ) from None
        if (
            type(observed) is not int
            or observed < self._last_observed_monotonic_ns
            or observed > _MAXIMUM_MONOTONIC_NANOSECONDS
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop deadline clock is invalid"
            )
        self._last_observed_monotonic_ns = observed
        if observed >= self._deadline_monotonic_ns:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop verification phase expired"
            )
        return observed

    def require_remaining(self, minimum_remaining_ns: int = 0) -> int:
        if type(minimum_remaining_ns) is not int or minimum_remaining_ns < 0:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop operation reserve is invalid"
            )
        remaining = self._deadline_monotonic_ns - self.observe()
        if remaining <= minimum_remaining_ns:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop operation cannot fit its phase"
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
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop SQL deadline is already active"
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
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop SQL operation is outside its phase"
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
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop provider deadline is already active"
            )
        self._guard = guard

    def deactivate(self, guard: _VerificationPhaseGuard) -> None:
        if self._guard is guard:
            self._guard = None

    def _require_guard(self) -> _VerificationPhaseGuard:
        guard = self._guard
        if guard is None:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop provider operation is outside its phase"
            )
        self._provider._timeout_seconds = guard.remote_timeout_seconds()
        return guard

    def attest_identity(self) -> object:
        guard = self._require_guard()
        result = self._provider.attest_identity()
        guard.require_remaining()
        return result

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        guard = self._require_guard()
        result = self._provider.list_object_names_page(
            bucket_name=bucket_name,
            prefix=prefix,
            offset=offset,
            limit=limit,
        )
        guard.require_remaining()
        return result

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        guard = self._require_guard()
        result = self._provider.list_sequence_object_names(
            bucket_name=bucket_name,
            prefix=prefix,
            anchor_sequence=anchor_sequence,
        )
        guard.require_remaining()
        return result

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        guard = self._require_guard()
        result = self._provider.download_object(
            bucket_name=bucket_name,
            object_name=object_name,
        )
        guard.require_remaining()
        return result


class _ProductionResources:
    __slots__ = ("_authority", "_owner", "_provider", "_repository", "_router", "_verifier")

    def __init__(
        self,
        *,
        authority: TrustedTimeHeadAnchorAuthority,
        repository: SqlTrustedTimeHeadAnchorRepository,
        provider: _DeadlineBoundReadOnlyProvider,
        verifier: Ed25519TrustedTimeAnchorVerifier,
        router: _SqlDeadlineRouter,
        owner: _ResourceOwner,
    ) -> None:
        self._authority = authority
        self._repository = repository
        self._provider = provider
        self._verifier = verifier
        self._router = router
        self._owner = owner

    def _load_projection(self, guard: _VerificationPhaseGuard) -> _SqlProjection:
        guard.require_remaining(
            _SQL_CONNECT_TIMEOUT_SECONDS * 1_000_000_000 + _SQL_OPERATION_MARGIN_NANOSECONDS
        )
        authority = self._authority
        snapshot = _construct_owned_resource(
            owner=self._owner,
            constructor=lambda: self._repository.load_head_anchor_startup_snapshot(
                host_id=authority.host_id,
                deployment_identity_sha256=authority.deployment_identity_sha256,
                runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
                anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
                anchor_project_ref=authority.anchor_project_ref,
                bucket_name=authority.bucket_name,
                principal_id=authority.principal_id,
            ),
            cleanup=self._repository.discard_head_anchor_snapshot,
        )
        guard.require_remaining()
        return _capture_sql_projection(snapshot, authority=authority)

    def verify(self, guard: _VerificationPhaseGuard) -> _VerifiedObservation:
        self._router.activate(guard)
        self._provider.activate(guard)
        try:
            initial = self._load_projection(guard)
            authority = self._authority
            try:
                remote_observation_sha256 = verify_bounded_clean_stop_terminal_remote_postcondition(
                    initial.journal_tip,
                    provider=cast(TrustedTimeHeadAnchorProvider, self._provider),
                    verifier=self._verifier,
                    signing_key_id=authority.signing_key_id,
                    signing_public_key_sha256=authority.signing_public_key_sha256,
                    checkpoint_interval_seconds=(
                        TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                    ),
                    anchor_authority_sha256=authority.anchor_authority_sha256,
                )
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop remote terminal is unconfirmed"
                ) from None
            if not _is_sha256(remote_observation_sha256):
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop remote observation digest is invalid"
                )
            final = self._load_projection(guard)
            if final != initial:
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop SQL terminal drifted around provider observation"
                )
            completed = guard.observe()
            return _VerifiedObservation(
                projection=final,
                remote_observation_sha256=remote_observation_sha256,
                observation_started_monotonic_ns=guard.started_monotonic_ns,
                observation_completed_monotonic_ns=completed,
                deadline_monotonic_ns=guard.deadline_monotonic_ns,
            )
        finally:
            self._provider.deactivate(guard)
            self._router.deactivate(guard)


def _create_production_resources(
    *,
    database_url: str,
    configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
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
    return _ProductionResources(
        authority=authority,
        repository=repository,
        provider=_DeadlineBoundReadOnlyProvider(provider),
        verifier=configuration.verifier,
        router=router,
        owner=owner,
    )


def _production_verify_once(
    resources: object,
    guard: _VerificationPhaseGuard,
) -> _VerifiedObservation:
    if type(resources) is not _ProductionResources:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop resources are invalid"
        )
    return resources.verify(guard)


@dataclass(frozen=True, slots=True)
class _Dispatch:
    issuer_reference: weakref.ReferenceType[
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    ]
    reauthenticate: Callable[[], TrustedTimePostEnrollmentCleanStopTerminalPostcondition]
    revoke: Callable[[], None]
    consume_issuance: Callable[[object], None]
    binding_digest: Callable[[], str]
    configuration_digest: Callable[[], str]


class TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
    """Immutable, process-private, one-shot clean-stop observation issuer."""

    __slots__ = ("__weakref__", "_capability")

    _capability: _PostconditionCapability

    def __new__(cls) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer must be prepared"
        )

    def __setattr__(self, _: str, __: object) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer is immutable"
        )

    def __delattr__(self, _: str) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer is immutable"
        )

    def _dispatch(self) -> _Dispatch:
        if type(self) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop terminal issuer is invalid"
            )
        try:
            capability = self._capability
        except Exception:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop terminal issuer is invalid"
            ) from None
        return _resolve_issuer_dispatch(self, capability)

    @property
    def issuer_binding_sha256(self) -> str:
        return self._dispatch().binding_digest()

    @property
    def read_only_configuration_sha256(self) -> str:
        return self._dispatch().configuration_digest()

    def reauthenticate_clean_stop_terminal_once(
        self,
    ) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        return self._dispatch().reauthenticate()

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop terminal issuer cannot be serialized"
        )

    authority_granted = property(_never_authorized)
    database_secret_disclosed = property(_never_authorized)
    provider_terminal_currentness_authenticated = property(_never_authorized)
    no_new_record_authenticated = property(_never_authorized)
    durability_authenticated = property(_never_authorized)
    durable_stop_outcome_authenticated = property(_never_authorized)
    slot_authorized = property(_never_authorized)
    admission_authorized = property(_never_authorized)
    effect_authorized = property(_never_authorized)
    active_controller_authorized = property(_never_authorized)
    claim_retention_authorized = property(_never_authorized)
    clean_stop_authorized = property(_never_authorized)
    clean_stop_outcome_retention_authorized = property(_never_authorized)
    confirmed_start_outcome_authenticated = property(_never_authorized)
    container_removal_authorized = property(_never_authorized)
    controller_execution_authorized = property(_never_authorized)
    current_topology_authenticated = property(_never_authorized)
    decision_authenticated = property(_never_authorized)
    execution_admission_authorized = property(_never_authorized)
    execution_attempt_reservation_authorized = property(_never_authorized)
    freshness_authenticated = property(_never_authorized)
    graceful_stop_authorized = property(_never_authorized)
    network_removal_authorized = property(_never_authorized)
    operator_attestation_authenticated = property(_never_authorized)
    outcome_retention_authorized = property(_never_authorized)
    persistent_start_authorized = property(_never_authorized)
    persistent_topology_authenticated = property(_never_authorized)
    qualified = property(_never_authorized)
    rearm_authorized = property(_never_authorized)
    release_authorized = property(_never_authorized)
    retry_authorized = property(_never_authorized)
    runtime_start_authorized = property(_never_authorized)
    sequence_2_authorized = property(_never_authorized)
    shutdown_locator_authenticated = property(_never_authorized)
    shutdown_outcome_retention_authorized = property(_never_authorized)
    single_use_authenticated = property(_never_authorized)
    source_start_authorized = property(_never_authorized)
    source_stop_authorized = property(_never_authorized)
    start_execution_attempt_authenticated = property(_never_authorized)
    stop_attempt_reservation_authorized = property(_never_authorized)
    stop_decision_authenticated = property(_never_authorized)
    stop_execution_authorized = property(_never_authorized)
    success_outcome_retention_authorized = property(_never_authorized)
    supervisor_signal_authorized = property(_never_authorized)
    supervisor_start_authorized = property(_never_authorized)
    supervisor_stop_authorized = property(_never_authorized)
    target_authenticated = property(_never_authorized)
    topology_mutation_authorized = property(_never_authorized)
    volume_removal_authorized = property(_never_authorized)
    currentness_qualified = property(_never_authorized)
    freshness_qualified = property(_never_authorized)
    durable = property(_never_authorized)
    no_new_record_success = property(_never_authorized)
    stop_outcome_retained = property(_never_authorized)
    stop_attempt_slot_reserved = property(_never_authorized)
    stop_admission_qualified = property(_never_authorized)
    signal_authorized = property(_never_authorized)
    shutdown_authorized = property(_never_authorized)
    teardown_authorized = property(_never_authorized)
    watchdog_authorized = property(_never_authorized)
    operational_control_authorized = property(_never_authorized)
    readiness_authorized = property(_never_authorized)
    arming_authorized = property(_never_authorized)
    new_exposure_authorized = property(_never_authorized)
    broker_action_authorized = property(_never_authorized)
    automatic_rearm_authorized = property(_never_authorized)
    automatic_resume_authorized = property(_never_authorized)
    alert_delivery_authorized = property(_never_authorized)
    exposure_authorized = property(_never_authorized)
    paper_trading_authorized = property(_never_authorized)
    live_trading_authorized = property(_never_authorized)


def _issue_issuer() -> TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
    return cast(
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
        object.__new__(
            cast(type[Any], TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer)
        ),
    )


def _build_preparer_with_registry(
    *,
    register_dispatch: Callable[
        [
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
            object,
            _Dispatch,
        ],
        None,
    ],
    resource_factory: Callable[..., object] = _create_production_resources,
    verification_runner: Callable[[object, _VerificationPhaseGuard], _VerifiedObservation] = (
        _production_verify_once
    ),
    monotonic_ns: Callable[[], int] = _suspend_aware_monotonic_ns,
    process_id: Callable[[], int] = os.getpid,
    current_thread: Callable[[], threading.Thread] = threading.current_thread,
) -> Callable[..., TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer]:
    """Private dependency seam for focused hermetic tests."""

    if any(
        not callable(candidate)
        for candidate in (
            resource_factory,
            verification_runner,
            monotonic_ns,
            process_id,
            current_thread,
        )
    ):
        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
            "trusted-time clean-stop issuer dependencies are invalid"
        )

    def prepare(
        *,
        database_url: str,
        configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
    ) -> TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
        try:
            if type(configuration) is not TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration:
                raise ValueError
            configuration_binding = _capture_configuration_binding(configuration)
            private_configuration = configuration_binding.private_configuration
            exact_database_url = validate_database_url(database_url)
            if (
                runtime_database_project_ref(exact_database_url)
                != private_configuration.authority.runtime_database_project_ref
            ):
                raise ValueError
            owner_pid = process_id()
            owner_thread = current_thread()
            started = monotonic_ns()
            if (
                type(owner_pid) is not int
                or owner_pid <= 0
                or not isinstance(owner_thread, threading.Thread)
                or type(started) is not int
                or started < 0
                or started > _MAXIMUM_MONOTONIC_NANOSECONDS - _PHASE_TIMEOUT_NANOSECONDS
            ):
                raise ValueError
            deadline = started + _PHASE_TIMEOUT_NANOSECONDS
            configuration_sha256 = configuration_binding.public_configuration_sha256
            binding_digest = _sha256_payload(
                {
                    "configuration_sha256": configuration_sha256,
                    "contract_version": (
                        POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION
                    ),
                    "deadline_monotonic_ns": deadline,
                    "issuer_clock_contract_version": _ISSUER_CLOCK_CONTRACT_VERSION,
                    "observation_started_monotonic_ns": started,
                    "origin_pid": owner_pid,
                    "origin_thread_ident": owner_thread.ident,
                    "origin_thread_name": owner_thread.name,
                    "phase_timeout_nanoseconds": _PHASE_TIMEOUT_NANOSECONDS,
                    "runtime_database_project_ref": (
                        private_configuration.authority.runtime_database_project_ref
                    ),
                }
            )
            capability = cast(
                _PostconditionCapability,
                object.__new__(cast(type[Any], _PostconditionCapability)),
            )
            issuer = _issue_issuer()
            object.__setattr__(issuer, "_capability", capability)
            issuer_reference = weakref.ref(issuer)
            state_lock = threading.RLock()
            state: dict[str, Any] = {
                "binding_digest": binding_digest,
                "configuration_binding": configuration_binding,
                "configuration_digest": configuration_sha256,
                "database_url": exact_database_url,
                "deadline": deadline,
                "issuance_observation": None,
                "monotonic_clock": monotonic_ns,
                "owner": None,
                "owner_pid": owner_pid,
                "owner_thread": owner_thread,
                "started": started,
                "status": "prepared",
            }

            def require_origin() -> None:
                if process_id() != state.get("owner_pid") or current_thread() is not state.get(
                    "owner_thread"
                ):
                    raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                        "trusted-time clean-stop issuer crossed its process or thread"
                    )

            def cleanup(*, require_success: bool) -> None:
                owner = state.get("owner")
                state["owner"] = None
                state["database_url"] = None
                state["configuration_binding"] = None
                state["issuance_observation"] = None
                state["monotonic_clock"] = None
                if type(owner) is _ResourceOwner:
                    owner.close(require_success=require_success)
                tombstone = {
                    "binding_digest": state["binding_digest"],
                    "configuration_digest": state["configuration_digest"],
                    "owner_pid": state["owner_pid"],
                    "owner_thread": state["owner_thread"],
                    "status": state["status"],
                }
                state.clear()
                state.update(tombstone)

            def reauthenticate() -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
                with state_lock:
                    if state.get("status") != "prepared":
                        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                            "trusted-time clean-stop issuer is unavailable"
                        )
                    issued_result: object | None = None
                    try:
                        require_origin()
                        state["status"] = "in_flight"
                        guard = _VerificationPhaseGuard(
                            started_monotonic_ns=state["started"],
                            deadline_monotonic_ns=state["deadline"],
                            clock=state["monotonic_clock"],
                            owner_pid=state["owner_pid"],
                            owner_thread=state["owner_thread"],
                        )
                        owner = _ResourceOwner()
                        state["owner"] = owner
                        exact_binding = state["configuration_binding"]
                        if type(exact_binding) is not _ConfigurationBinding:
                            error_type = (
                                TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
                            )
                            raise error_type(
                                "trusted-time clean-stop configuration binding is unavailable"
                            )
                        exact_binding.revalidate()
                        resources = resource_factory(
                            database_url=state["database_url"],
                            configuration=exact_binding.private_configuration,
                            owner=owner,
                            owner_pid=state["owner_pid"],
                            owner_thread=state["owner_thread"],
                            initial_guard=guard,
                        )
                        observation = verification_runner(resources, guard)
                        if type(observation) is not _VerifiedObservation:
                            error_type = (
                                TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
                            )
                            raise error_type("trusted-time clean-stop observation is invalid")
                        observation.__post_init__()
                        if (
                            observation.observation_started_monotonic_ns
                            != guard.started_monotonic_ns
                            or observation.deadline_monotonic_ns != guard.deadline_monotonic_ns
                        ):
                            error_type = (
                                TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
                            )
                            raise error_type(
                                "trusted-time clean-stop observation crossed its issuer clock"
                            )
                        exact_binding.revalidate()
                        private_authority = exact_binding.private_configuration.authority
                        cleanup(require_success=True)
                        completed = guard.observe()
                        observation = _VerifiedObservation(
                            projection=observation.projection,
                            remote_observation_sha256=(observation.remote_observation_sha256),
                            observation_started_monotonic_ns=guard.started_monotonic_ns,
                            observation_completed_monotonic_ns=completed,
                            deadline_monotonic_ns=guard.deadline_monotonic_ns,
                        )
                        exact_binding.revalidate()
                        state["issuance_observation"] = observation
                        exact_issuer = issuer_reference()
                        if exact_issuer is None:
                            error_type = (
                                TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
                            )
                            raise error_type("trusted-time clean-stop issuer is unavailable")
                        issued_result = _issue_postcondition(
                            issuer=exact_issuer,
                            issuer_capability=capability,
                            observation=observation,
                            authority=private_authority,
                            issuer_binding_sha256=state["binding_digest"],
                            configuration_sha256=state["configuration_digest"],
                            owner_pid=state["owner_pid"],
                            owner_thread=state["owner_thread"],
                        )
                        issued_result.__post_init__()
                        state["status"] = "confirmed"
                        return issued_result
                    except BaseException as error:
                        _revoke_issued_postcondition(
                            issued_result,
                            issuer_capability=capability,
                        )
                        state["status"] = "closed"
                        cleanup(require_success=False)
                        if not isinstance(error, Exception):
                            raise
                        if isinstance(
                            error,
                            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected,
                        ):
                            raise
                        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                            "trusted-time clean-stop terminal reauthentication is unconfirmed"
                        ) from None

            def revoke() -> None:
                with state_lock:
                    if state.get("status") in {"closed", "confirmed"}:
                        return
                    state["status"] = "closed"
                    cleanup(require_success=False)

            def consume_issuance(candidate: object) -> None:
                with state_lock:
                    require_origin()
                    if (
                        state.get("status") != "in_flight"
                        or type(candidate) is not _VerifiedObservation
                        or state.get("issuance_observation") is not candidate
                    ):
                        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                            "trusted-time clean-stop issuance authorization is unavailable"
                        )
                    state["issuance_observation"] = None

            def read_binding_digest() -> str:
                with state_lock:
                    require_origin()
                    value = state.get("binding_digest")
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                            "trusted-time clean-stop issuer binding is unavailable"
                        )
                    return cast(str, value)

            def read_configuration_digest() -> str:
                with state_lock:
                    require_origin()
                    value = state.get("configuration_digest")
                    if not _is_sha256(value):
                        raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                            "trusted-time clean-stop configuration binding is unavailable"
                        )
                    return cast(str, value)

            register_dispatch(
                issuer,
                capability,
                _Dispatch(
                    issuer_reference=issuer_reference,
                    reauthenticate=reauthenticate,
                    revoke=revoke,
                    consume_issuance=consume_issuance,
                    binding_digest=read_binding_digest,
                    configuration_digest=read_configuration_digest,
                ),
            )
            return issuer
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop issuer preparation failed"
            ) from None

    return prepare


def _build_registry() -> tuple[
    Callable[
        [TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer, object],
        _Dispatch,
    ],
    Callable[..., Callable[..., TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer]],
    Any,
]:
    origin_pid = os.getpid()
    registry_lock = threading.Lock()
    registry: dict[_PostconditionCapability, _Dispatch] = {}

    def register_dispatch(
        issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
        capability: object,
        dispatch: _Dispatch,
    ) -> None:
        if (
            os.getpid() != origin_pid
            or type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            or type(capability) is not _PostconditionCapability
            or type(dispatch) is not _Dispatch
            or dispatch.issuer_reference() is not issuer
        ):
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop issuer registration is invalid"
            )
        exact_capability = cast(_PostconditionCapability, capability)

        def issuer_lost(
            reference: weakref.ReferenceType[
                TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
            ],
        ) -> None:
            if os.getpid() != origin_pid:
                return
            with registry_lock:
                current = registry.get(exact_capability)
                if current is None or current.issuer_reference is not reference:
                    return
                registry.pop(exact_capability, None)
            with suppress(BaseException):
                current.revoke()

        registered = _Dispatch(
            issuer_reference=weakref.ref(issuer, issuer_lost),
            reauthenticate=dispatch.reauthenticate,
            revoke=dispatch.revoke,
            consume_issuance=dispatch.consume_issuance,
            binding_digest=dispatch.binding_digest,
            configuration_digest=dispatch.configuration_digest,
        )
        with registry_lock:
            if exact_capability in registry:
                raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                    "trusted-time clean-stop issuer registration was replayed"
                )
            registry[exact_capability] = registered

    def resolve_dispatch(
        issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
        capability: object,
    ) -> _Dispatch:
        if os.getpid() != origin_pid or type(capability) is not _PostconditionCapability:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop issuer is unavailable"
            )
        with registry_lock:
            dispatch = registry.get(cast(_PostconditionCapability, capability))
        if dispatch is None or dispatch.issuer_reference() is not issuer:
            raise TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected(
                "trusted-time clean-stop issuer is unavailable"
            )
        return dispatch

    def build_preparer(
        *,
        resource_factory: Callable[..., object] = _create_production_resources,
        verification_runner: Callable[[object, _VerificationPhaseGuard], _VerifiedObservation] = (
            _production_verify_once
        ),
        monotonic_ns: Callable[[], int] = _suspend_aware_monotonic_ns,
        process_id: Callable[[], int] = os.getpid,
        current_thread: Callable[[], threading.Thread] = threading.current_thread,
    ) -> Callable[..., TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer]:
        return _build_preparer_with_registry(
            register_dispatch=register_dispatch,
            resource_factory=resource_factory,
            verification_runner=verification_runner,
            monotonic_ns=monotonic_ns,
            process_id=process_id,
            current_thread=current_thread,
        )

    return resolve_dispatch, build_preparer, registry_lock


(
    _resolve_issuer_dispatch,
    _build_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_preparer,
    _ISSUER_DISPATCH_REGISTRY_LOCK,
) = _build_registry()
del _build_registry


prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer = (
    _build_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_preparer()
)


__all__ = [
    "POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION",
    "TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration",
    "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
    "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
    "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected",
    "prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer",
]
