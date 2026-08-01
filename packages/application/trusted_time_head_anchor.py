"""Provider-neutral external checkpoints for authenticated trusted-time heads.

The caller supplies a complete, already authenticated local head-transition
chain.  This module verifies a sparse signed remote checkpoint chain and, when
the local chain is ahead, appends exactly one checkpoint for its current head.
Checkpoint cadence and reason selection remain outside this module.

An external checkpoint is evidence that one exact local head was signed and
stored outside the local journal.  In particular, enrollment does not
retroactively authenticate earlier local history, and no result grants
readiness, control, exposure, re-arm, resume, or broker authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from _thread import LockType
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, SupportsIndex, cast
from uuid import UUID

from packages.application.trusted_time_monitor import TrustedTimeProbeStatus
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.trusted_time import (
    TRUSTED_TIME_POLICY,
    TrustedTimeHealth,
    TrustedTimeReason,
)

TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION = (
    "phase6d-provider-neutral-external-trusted-head-anchor-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME = "aqt-trusted-time-anchors-v1"
TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE = "application/json"
TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION = (
    "phase6a-durable-trusted-time-persistence-v2"
)
MAX_TRUSTED_TIME_HEAD_ANCHOR_BYTES = 4_096
MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE = 9_223_372_036_854_775_807
TRUSTED_TIME_HEAD_ANCHOR_FULL_AUDIT_PAGE_SIZE = 1_000
TRUSTED_TIME_HEAD_ANCHOR_FULL_AUDIT_MAX_OBJECTS = 250_000

_CANONICAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
_OBJECT_NAME = re.compile(r"([0-9]{20})-([0-9a-f]{64})\.json\Z")
_PROJECT_REF = re.compile(r"[a-z0-9]{20}\Z", re.ASCII)

TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS = 300
TRUSTED_TIME_HEAD_ANCHOR_SUPPORTED_POLICY_SHA256 = frozenset({TRUSTED_TIME_POLICY.semantic_sha256})
TRUSTED_TIME_HEAD_ANCHOR_SUPPORTED_PERSISTENCE_CONTRACT_VERSIONS = frozenset(
    {TRUSTED_TIME_HEAD_ANCHOR_PERSISTENCE_CONTRACT_VERSION}
)


class TrustedTimeHeadAnchorCheckpointReason(StrEnum):
    ENROLLMENT = "enrollment"
    EPOCH_ROTATION = "epoch_rotation"
    PERIODIC = "periodic"
    HARD_FAILURE = "hard_failure"
    HEALTH_TRANSITION = "health_transition"
    RECOVERY_TRANSITION = "recovery_transition"
    CLEAN_STOP = "clean_stop"
    ON_DEMAND = "on_demand"


class TrustedTimeHeadAnchorError(RuntimeError):
    """External trusted-head evidence is malformed, conflicting, or unavailable."""


class TrustedTimeHeadAnchorConflict(TrustedTimeHeadAnchorError):
    """Remote evidence conflicts with the complete authenticated local chain."""


class TrustedTimeHeadAnchorProviderUnavailable(TrustedTimeHeadAnchorError):
    """A provider explicitly classified a retryable availability failure."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise TrustedTimeHeadAnchorError(f"{field_name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise TrustedTimeHeadAnchorError(f"{field_name} contains unsupported text")
    return value


def _require_bucket_name(value: object) -> str:
    bucket = _require_text(value, "trusted-time anchor bucket", maximum=128)
    if bucket != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor bucket must match the exact admitted bucket"
        )
    return bucket


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeHeadAnchorError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_uuid(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise TrustedTimeHeadAnchorError(f"{field_name} must be a canonical UUID") from None
    if parsed.int == 0 or str(parsed) != value:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be a non-nil canonical UUID")
    return value


def _require_project_ref(value: object) -> str:
    project_ref = _require_text(value, "trusted-time anchor project ref", maximum=20)
    if _PROJECT_REF.fullmatch(project_ref) is None:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor project ref must be 20 lowercase alphanumeric characters"
        )
    return project_ref


def _require_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise TrustedTimeHeadAnchorError(f"{field_name} must be UTC")
    return value


def _require_positive_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be a positive signed 64-bit integer")
    return value


def _require_non_negative_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE:
        raise TrustedTimeHeadAnchorError(
            f"{field_name} must be a non-negative signed 64-bit integer"
        )
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_ed25519_signature(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 128
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor Ed25519 signature must be 64 lowercase hexadecimal bytes"
        )
    return value


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorProviderIdentity:
    """Physical object-provider identity attested independently of record bytes."""

    anchor_project_identity_sha256: str
    anchor_project_ref: str
    principal_id: str
    bucket_name: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.anchor_project_identity_sha256,
            "trusted-time provider project identity SHA-256",
        )
        _require_project_ref(self.anchor_project_ref)
        _require_uuid(self.principal_id, "trusted-time provider principal ID")
        _require_bucket_name(self.bucket_name)


@dataclass(frozen=True, slots=True)
class AuthenticatedTrustedTimeHeadTransition:
    """One exact host-head transition after complete local journal authentication."""

    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    head_authenticated_at_utc: datetime
    host_id: str
    source_id: str
    source_authority_sha256: str
    policy_sha256: str
    persistence_contract_version: str
    epoch_sequence: int
    monitor_epoch_id: str
    epoch_sha256: str
    evaluation_sequence: int
    evaluation_id: str | None
    evaluation_record_sha256: str | None
    state_sha256: str | None
    probe_status: TrustedTimeProbeStatus | None
    health: TrustedTimeHealth | None
    reason: TrustedTimeReason | None
    hard_failure_latched: bool | None
    clock_recovery_qualified: bool | None
    evaluated_at_utc: datetime | None
    evaluated_at_monotonic_ns: int | None
    previous_host_head_sha256: str | None
    current_host_head_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.deployment_identity_sha256,
            "trusted-time anchor deployment identity SHA-256",
        )
        _require_sha256(
            self.runtime_database_identity_sha256,
            "trusted-time anchor runtime-database identity SHA-256",
        )
        _require_sha256(
            self.anchor_project_identity_sha256,
            "trusted-time anchor project identity SHA-256",
        )
        _require_project_ref(self.anchor_project_ref)
        _require_bucket_name(self.bucket_name)
        _require_uuid(self.principal_id, "trusted-time anchor principal ID")
        _require_utc(
            self.head_authenticated_at_utc,
            "trusted-time head authentication instant",
        )
        _require_text(self.host_id, "trusted-time anchor host ID")
        _require_text(self.source_id, "trusted-time anchor source ID")
        _require_sha256(
            self.source_authority_sha256,
            "trusted-time anchor source authority SHA-256",
        )
        _require_sha256(self.policy_sha256, "trusted-time anchor policy SHA-256")
        if self.policy_sha256 not in TRUSTED_TIME_HEAD_ANCHOR_SUPPORTED_POLICY_SHA256:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor policy SHA-256 is not admitted by this contract"
            )
        _require_text(
            self.persistence_contract_version,
            "trusted-time persistence contract version",
        )
        if self.persistence_contract_version not in (
            TRUSTED_TIME_HEAD_ANCHOR_SUPPORTED_PERSISTENCE_CONTRACT_VERSIONS
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor persistence contract version is unsupported"
            )
        _require_positive_integer(self.epoch_sequence, "trusted-time anchor epoch sequence")
        _require_uuid(self.monitor_epoch_id, "trusted-time anchor monitor epoch ID")
        _require_sha256(self.epoch_sha256, "trusted-time anchor epoch SHA-256")
        _require_non_negative_integer(
            self.evaluation_sequence,
            "trusted-time anchor evaluation sequence",
        )
        evaluation_id = self.evaluation_id
        if evaluation_id is not None:
            _require_uuid(evaluation_id, "trusted-time anchor evaluation ID")
        evaluation_record = _require_optional_sha256(
            self.evaluation_record_sha256,
            "trusted-time anchor evaluation-record SHA-256",
        )
        state = _require_optional_sha256(
            self.state_sha256,
            "trusted-time anchor state SHA-256",
        )
        projection = (
            evaluation_id,
            evaluation_record,
            state,
            self.probe_status,
            self.health,
            self.reason,
            self.hard_failure_latched,
            self.clock_recovery_qualified,
            self.evaluated_at_utc,
            self.evaluated_at_monotonic_ns,
        )
        if (self.evaluation_sequence == 0) != all(value is None for value in projection):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor evaluation zero requires an entirely null state projection"
            )
        if self.evaluation_sequence > 0 and any(value is None for value in projection):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor evaluated head requires a complete state projection"
            )
        if self.probe_status is not None and type(self.probe_status) is not TrustedTimeProbeStatus:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor probe status must be an exact enum"
            )
        if self.health is not None and type(self.health) is not TrustedTimeHealth:
            raise TrustedTimeHeadAnchorError("trusted-time anchor health must be an exact enum")
        if self.reason is not None and type(self.reason) is not TrustedTimeReason:
            raise TrustedTimeHeadAnchorError("trusted-time anchor reason must be an exact enum")
        for flag, field_name in (
            (self.hard_failure_latched, "hard-failure latch"),
            (self.clock_recovery_qualified, "clock-recovery qualification"),
        ):
            if flag is not None and type(flag) is not bool:
                raise TrustedTimeHeadAnchorError(
                    f"trusted-time anchor {field_name} must be an exact boolean"
                )
        if self.evaluated_at_monotonic_ns is not None:
            _require_non_negative_integer(
                self.evaluated_at_monotonic_ns,
                "trusted-time anchor evaluated monotonic nanoseconds",
            )
        if self.evaluated_at_utc is not None:
            _require_utc(
                self.evaluated_at_utc,
                "trusted-time anchor evaluated UTC instant",
            )
            if self.evaluated_at_utc != self.head_authenticated_at_utc:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time evaluated UTC instant conflicts with head authentication"
                )
        previous_head = _require_optional_sha256(
            self.previous_host_head_sha256,
            "trusted-time anchor previous host-head SHA-256",
        )
        local_genesis = self.epoch_sequence == 1 and self.evaluation_sequence == 0
        if (previous_head is None) != local_genesis:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor previous host head may be null only at local chain genesis"
            )
        _require_sha256(
            self.current_host_head_sha256,
            "trusted-time anchor current host-head SHA-256",
        )
        if previous_head == self.current_host_head_sha256:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor host-head transition must advance"
            )


def _anchor_semantic_material(
    *,
    anchor_sequence: int,
    deployment_identity_sha256: str,
    runtime_database_identity_sha256: str,
    anchor_project_identity_sha256: str,
    anchor_project_ref: str,
    bucket_name: str,
    principal_id: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
    head_authenticated_at_utc: datetime,
    host_id: str,
    source_id: str,
    source_authority_sha256: str,
    policy_sha256: str,
    persistence_contract_version: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    epoch_sequence: int,
    monitor_epoch_id: str,
    epoch_sha256: str,
    evaluation_sequence: int,
    evaluation_id: str | None,
    evaluation_record_sha256: str | None,
    state_sha256: str | None,
    probe_status: TrustedTimeProbeStatus | None,
    health: TrustedTimeHealth | None,
    reason: TrustedTimeReason | None,
    hard_failure_latched: bool | None,
    clock_recovery_qualified: bool | None,
    evaluated_at_utc: datetime | None,
    evaluated_at_monotonic_ns: int | None,
    previous_anchor_sha256: str | None,
    previous_anchored_host_head_sha256: str | None,
    local_previous_host_head_sha256: str | None,
    current_host_head_sha256: str,
) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION,
        "trusted_time_head_anchor_semantic",
        anchor_sequence,
        deployment_identity_sha256,
        runtime_database_identity_sha256,
        anchor_project_identity_sha256,
        anchor_project_ref,
        bucket_name,
        principal_id,
        signing_key_id,
        signing_public_key_sha256,
        head_authenticated_at_utc,
        host_id,
        source_id,
        source_authority_sha256,
        policy_sha256,
        persistence_contract_version,
        checkpoint_reason.value,
        checkpoint_interval_seconds,
        anchor_authority_sha256,
        epoch_sequence,
        monitor_epoch_id,
        epoch_sha256,
        evaluation_sequence,
        evaluation_id,
        evaluation_record_sha256,
        state_sha256,
        None if probe_status is None else probe_status.value,
        None if health is None else health.value,
        None if reason is None else reason.value,
        hard_failure_latched,
        clock_recovery_qualified,
        evaluated_at_utc,
        evaluated_at_monotonic_ns,
        previous_anchor_sha256,
        previous_anchored_host_head_sha256,
        local_previous_host_head_sha256,
        current_host_head_sha256,
    )


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorRecord:
    """One canonical, content-authenticated, Ed25519-signed remote checkpoint."""

    anchor_sequence: int
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    signing_key_id: str
    signing_public_key_sha256: str
    head_authenticated_at_utc: datetime
    host_id: str
    source_id: str
    source_authority_sha256: str
    policy_sha256: str
    persistence_contract_version: str
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    checkpoint_interval_seconds: int
    anchor_authority_sha256: str
    epoch_sequence: int
    monitor_epoch_id: str
    epoch_sha256: str
    evaluation_sequence: int
    evaluation_id: str | None
    evaluation_record_sha256: str | None
    state_sha256: str | None
    probe_status: TrustedTimeProbeStatus | None
    health: TrustedTimeHealth | None
    reason: TrustedTimeReason | None
    hard_failure_latched: bool | None
    clock_recovery_qualified: bool | None
    evaluated_at_utc: datetime | None
    evaluated_at_monotonic_ns: int | None
    previous_anchor_sha256: str | None
    previous_anchored_host_head_sha256: str | None
    local_previous_host_head_sha256: str | None
    current_host_head_sha256: str
    semantic_sha256: str
    signature_ed25519: str

    def __post_init__(self) -> None:
        transition = AuthenticatedTrustedTimeHeadTransition(
            deployment_identity_sha256=self.deployment_identity_sha256,
            runtime_database_identity_sha256=self.runtime_database_identity_sha256,
            anchor_project_identity_sha256=self.anchor_project_identity_sha256,
            anchor_project_ref=self.anchor_project_ref,
            bucket_name=self.bucket_name,
            principal_id=self.principal_id,
            head_authenticated_at_utc=self.head_authenticated_at_utc,
            host_id=self.host_id,
            source_id=self.source_id,
            source_authority_sha256=self.source_authority_sha256,
            policy_sha256=self.policy_sha256,
            persistence_contract_version=self.persistence_contract_version,
            epoch_sequence=self.epoch_sequence,
            monitor_epoch_id=self.monitor_epoch_id,
            epoch_sha256=self.epoch_sha256,
            evaluation_sequence=self.evaluation_sequence,
            evaluation_id=self.evaluation_id,
            evaluation_record_sha256=self.evaluation_record_sha256,
            state_sha256=self.state_sha256,
            probe_status=self.probe_status,
            health=self.health,
            reason=self.reason,
            hard_failure_latched=self.hard_failure_latched,
            clock_recovery_qualified=self.clock_recovery_qualified,
            evaluated_at_utc=self.evaluated_at_utc,
            evaluated_at_monotonic_ns=self.evaluated_at_monotonic_ns,
            previous_host_head_sha256=self.local_previous_host_head_sha256,
            current_host_head_sha256=self.current_host_head_sha256,
        )
        _require_positive_integer(
            self.anchor_sequence,
            "trusted-time remote anchor sequence",
        )
        _require_text(self.signing_key_id, "trusted-time anchor signing-key ID")
        _require_sha256(
            self.signing_public_key_sha256,
            "trusted-time anchor signing public-key SHA-256",
        )
        if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor checkpoint reason must be an exact enum"
            )
        if (
            type(self.checkpoint_interval_seconds) is not int
            or self.checkpoint_interval_seconds
            != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor checkpoint interval must be exactly 300 seconds"
            )
        _require_sha256(
            self.anchor_authority_sha256,
            "trusted-time anchor authority SHA-256",
        )
        previous_anchor = _require_optional_sha256(
            self.previous_anchor_sha256,
            "trusted-time previous anchor SHA-256",
        )
        previous_anchored_head = _require_optional_sha256(
            self.previous_anchored_host_head_sha256,
            "trusted-time previous anchored host-head SHA-256",
        )
        if (self.anchor_sequence == 1) != (
            previous_anchor is None and previous_anchored_head is None
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time first remote anchor requires null remote predecessors"
            )
        if (previous_anchor is None) != (previous_anchored_head is None):
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor predecessors must be null together"
            )
        if (self.anchor_sequence == 1) != (
            self.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time enrollment reason is permitted only for anchor sequence one"
            )
        expected_semantic_sha256 = _sha256(
            _anchor_semantic_material(
                anchor_sequence=self.anchor_sequence,
                deployment_identity_sha256=transition.deployment_identity_sha256,
                runtime_database_identity_sha256=(transition.runtime_database_identity_sha256),
                anchor_project_identity_sha256=(transition.anchor_project_identity_sha256),
                anchor_project_ref=transition.anchor_project_ref,
                bucket_name=transition.bucket_name,
                principal_id=transition.principal_id,
                signing_key_id=self.signing_key_id,
                signing_public_key_sha256=self.signing_public_key_sha256,
                head_authenticated_at_utc=transition.head_authenticated_at_utc,
                host_id=transition.host_id,
                source_id=transition.source_id,
                source_authority_sha256=transition.source_authority_sha256,
                policy_sha256=transition.policy_sha256,
                persistence_contract_version=transition.persistence_contract_version,
                checkpoint_reason=self.checkpoint_reason,
                checkpoint_interval_seconds=self.checkpoint_interval_seconds,
                anchor_authority_sha256=self.anchor_authority_sha256,
                epoch_sequence=transition.epoch_sequence,
                monitor_epoch_id=transition.monitor_epoch_id,
                epoch_sha256=transition.epoch_sha256,
                evaluation_sequence=transition.evaluation_sequence,
                evaluation_id=transition.evaluation_id,
                evaluation_record_sha256=transition.evaluation_record_sha256,
                state_sha256=transition.state_sha256,
                probe_status=transition.probe_status,
                health=transition.health,
                reason=transition.reason,
                hard_failure_latched=transition.hard_failure_latched,
                clock_recovery_qualified=transition.clock_recovery_qualified,
                evaluated_at_utc=transition.evaluated_at_utc,
                evaluated_at_monotonic_ns=transition.evaluated_at_monotonic_ns,
                previous_anchor_sha256=previous_anchor,
                previous_anchored_host_head_sha256=previous_anchored_head,
                local_previous_host_head_sha256=transition.previous_host_head_sha256,
                current_host_head_sha256=transition.current_host_head_sha256,
            )
        )
        _require_sha256(
            self.semantic_sha256,
            "trusted-time anchor semantic SHA-256",
        )
        if self.semantic_sha256 != expected_semantic_sha256:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor semantic SHA-256 conflicts with canonical material"
            )
        _require_ed25519_signature(self.signature_ed25519)

    def _semantic_material(self) -> tuple[object, ...]:
        return _anchor_semantic_material(
            anchor_sequence=self.anchor_sequence,
            deployment_identity_sha256=self.deployment_identity_sha256,
            runtime_database_identity_sha256=self.runtime_database_identity_sha256,
            anchor_project_identity_sha256=self.anchor_project_identity_sha256,
            anchor_project_ref=self.anchor_project_ref,
            bucket_name=self.bucket_name,
            principal_id=self.principal_id,
            signing_key_id=self.signing_key_id,
            signing_public_key_sha256=self.signing_public_key_sha256,
            head_authenticated_at_utc=self.head_authenticated_at_utc,
            host_id=self.host_id,
            source_id=self.source_id,
            source_authority_sha256=self.source_authority_sha256,
            policy_sha256=self.policy_sha256,
            persistence_contract_version=self.persistence_contract_version,
            checkpoint_reason=self.checkpoint_reason,
            checkpoint_interval_seconds=self.checkpoint_interval_seconds,
            anchor_authority_sha256=self.anchor_authority_sha256,
            epoch_sequence=self.epoch_sequence,
            monitor_epoch_id=self.monitor_epoch_id,
            epoch_sha256=self.epoch_sha256,
            evaluation_sequence=self.evaluation_sequence,
            evaluation_id=self.evaluation_id,
            evaluation_record_sha256=self.evaluation_record_sha256,
            state_sha256=self.state_sha256,
            probe_status=self.probe_status,
            health=self.health,
            reason=self.reason,
            hard_failure_latched=self.hard_failure_latched,
            clock_recovery_qualified=self.clock_recovery_qualified,
            evaluated_at_utc=self.evaluated_at_utc,
            evaluated_at_monotonic_ns=self.evaluated_at_monotonic_ns,
            previous_anchor_sha256=self.previous_anchor_sha256,
            previous_anchored_host_head_sha256=self.previous_anchored_host_head_sha256,
            local_previous_host_head_sha256=self.local_previous_host_head_sha256,
            current_host_head_sha256=self.current_host_head_sha256,
        )

    @property
    def signed_payload(self) -> bytes:
        """Exact canonical bytes covered by the Ed25519 signature."""

        return canonical_json_bytes(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION,
                "trusted_time_head_anchor_signed_envelope",
                self._semantic_material(),
                self.semantic_sha256,
                self.signature_ed25519,
            )
        )

    @property
    def canonical_bytes(self) -> bytes:
        return self.canonical_json.encode("utf-8")

    @property
    def byte_sha256(self) -> str:
        return _sha256_bytes(self.canonical_bytes)

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> TrustedTimeHeadAnchorRecord:
        """Strictly decode, revalidate, and re-canonicalize one remote object."""

        if type(payload) is not bytes or not payload:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor payload must be non-empty exact bytes"
            )
        if len(payload) > MAX_TRUSTED_TIME_HEAD_ANCHOR_BYTES:
            raise TrustedTimeHeadAnchorError("trusted-time remote anchor payload is oversized")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor payload must be UTF-8"
            ) from None
        try:
            decoded = _decode_canonical_typed_json(text)
            envelope = _expect_tuple(decoded, "trusted-time signed anchor envelope", size=5)
            if envelope[0] != TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION:
                raise TrustedTimeHeadAnchorError(
                    "trusted-time remote anchor contract version is unsupported"
                )
            if envelope[1] != "trusted_time_head_anchor_signed_envelope":
                raise TrustedTimeHeadAnchorError(
                    "trusted-time remote anchor envelope kind is unsupported"
                )
            material = _expect_tuple(
                envelope[2],
                "trusted-time anchor semantic material",
                size=38,
            )
            if (
                material[0] != TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION
                or material[1] != "trusted_time_head_anchor_semantic"
            ):
                raise TrustedTimeHeadAnchorError(
                    "trusted-time anchor semantic contract is unsupported"
                )
            record = cls(
                anchor_sequence=_expect_integer(material[2], "anchor sequence"),
                deployment_identity_sha256=_expect_string(
                    material[3],
                    "deployment identity",
                ),
                runtime_database_identity_sha256=_expect_string(
                    material[4],
                    "runtime-database identity",
                ),
                anchor_project_identity_sha256=_expect_string(
                    material[5],
                    "anchor-project identity",
                ),
                anchor_project_ref=_expect_string(material[6], "anchor-project ref"),
                bucket_name=_expect_string(material[7], "bucket name"),
                principal_id=_expect_string(material[8], "principal ID"),
                signing_key_id=_expect_string(material[9], "signing-key ID"),
                signing_public_key_sha256=_expect_string(
                    material[10],
                    "signing public-key SHA-256",
                ),
                head_authenticated_at_utc=_expect_datetime(
                    material[11],
                    "head authentication instant",
                ),
                host_id=_expect_string(material[12], "host ID"),
                source_id=_expect_string(material[13], "source ID"),
                source_authority_sha256=_expect_string(
                    material[14],
                    "source authority SHA-256",
                ),
                policy_sha256=_expect_string(material[15], "policy SHA-256"),
                persistence_contract_version=_expect_string(
                    material[16],
                    "persistence contract version",
                ),
                checkpoint_reason=_expect_checkpoint_reason(material[17]),
                checkpoint_interval_seconds=_expect_integer(
                    material[18],
                    "checkpoint interval seconds",
                ),
                anchor_authority_sha256=_expect_string(
                    material[19],
                    "anchor authority SHA-256",
                ),
                epoch_sequence=_expect_integer(material[20], "epoch sequence"),
                monitor_epoch_id=_expect_string(material[21], "monitor epoch ID"),
                epoch_sha256=_expect_string(material[22], "epoch SHA-256"),
                evaluation_sequence=_expect_integer(
                    material[23],
                    "evaluation sequence",
                ),
                evaluation_id=_expect_optional_string(material[24], "evaluation ID"),
                evaluation_record_sha256=_expect_optional_string(
                    material[25],
                    "evaluation-record SHA-256",
                ),
                state_sha256=_expect_optional_string(material[26], "state SHA-256"),
                probe_status=_expect_optional_probe_status(material[27]),
                health=_expect_optional_health(material[28]),
                reason=_expect_optional_reason(material[29]),
                hard_failure_latched=_expect_optional_boolean(
                    material[30],
                    "hard-failure latch",
                ),
                clock_recovery_qualified=_expect_optional_boolean(
                    material[31],
                    "clock-recovery qualification",
                ),
                evaluated_at_utc=_expect_optional_datetime(
                    material[32],
                    "evaluated UTC instant",
                ),
                evaluated_at_monotonic_ns=_expect_optional_integer(
                    material[33],
                    "evaluated monotonic nanoseconds",
                ),
                previous_anchor_sha256=_expect_optional_string(
                    material[34],
                    "previous anchor SHA-256",
                ),
                previous_anchored_host_head_sha256=_expect_optional_string(
                    material[35],
                    "previous anchored host-head SHA-256",
                ),
                local_previous_host_head_sha256=_expect_optional_string(
                    material[36],
                    "local previous host-head SHA-256",
                ),
                current_host_head_sha256=_expect_string(
                    material[37],
                    "current host-head SHA-256",
                ),
                semantic_sha256=_expect_string(envelope[3], "anchor semantic SHA-256"),
                signature_ed25519=_expect_string(envelope[4], "Ed25519 signature"),
            )
        except TrustedTimeHeadAnchorError:
            raise
        except (OverflowError, TypeError, ValueError):
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor payload is malformed"
            ) from None
        if record.canonical_bytes != payload:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor payload is not byte-exact canonical JSON"
            )
        return record


_AUTHENTICATED_JOURNAL_TIP_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedTrustedTimeHeadJournalTip:
    """Application-owned compact proof of an authenticated durable prefix."""

    current_transition: AuthenticatedTrustedTimeHeadTransition
    local_transition_count: int
    first_local_host_head_sha256: str
    current_local_host_head_sha256: str
    confirmed_anchor_count: int
    confirmed_anchor_tip: TrustedTimeHeadAnchorRecord | None
    first_anchored_local_transition_ordinal: int | None
    confirmed_anchor_local_transition_ordinal: int | None
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    _seal: object = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError(
            "AuthenticatedTrustedTimeHeadJournalTip is issued by authenticated persistence"
        )

    def __post_init__(self) -> None:
        if self._seal is not _AUTHENTICATED_JOURNAL_TIP_SEAL:
            raise TrustedTimeHeadAnchorError(
                "trusted-time authenticated journal tip is not authentic"
            )
        if type(self.current_transition) is not AuthenticatedTrustedTimeHeadTransition:
            raise TrustedTimeHeadAnchorError(
                "trusted-time authenticated journal tip transition must be exact"
            )
        self.current_transition.__post_init__()
        local_count = _require_positive_integer(
            self.local_transition_count,
            "trusted-time authenticated journal local transition count",
        )
        first_head = _require_sha256(
            self.first_local_host_head_sha256,
            "trusted-time authenticated journal first local head SHA-256",
        )
        current_head = _require_sha256(
            self.current_local_host_head_sha256,
            "trusted-time authenticated journal current local head SHA-256",
        )
        if current_head != self.current_transition.current_host_head_sha256:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal current head conflicts"
            )
        if local_count == 1 and first_head != current_head:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal singleton head conflicts"
            )
        identity = self.current_transition
        pins = (
            (
                _require_sha256(
                    self.deployment_identity_sha256,
                    "trusted-time authenticated journal deployment identity SHA-256",
                ),
                identity.deployment_identity_sha256,
            ),
            (
                _require_sha256(
                    self.runtime_database_identity_sha256,
                    "trusted-time authenticated journal runtime-database identity SHA-256",
                ),
                identity.runtime_database_identity_sha256,
            ),
            (
                _require_sha256(
                    self.anchor_project_identity_sha256,
                    "trusted-time authenticated journal project identity SHA-256",
                ),
                identity.anchor_project_identity_sha256,
            ),
            (_require_project_ref(self.anchor_project_ref), identity.anchor_project_ref),
            (_require_bucket_name(self.bucket_name), identity.bucket_name),
            (
                _require_uuid(
                    self.principal_id,
                    "trusted-time authenticated journal principal ID",
                ),
                identity.principal_id,
            ),
        )
        if any(actual != expected for actual, expected in pins):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal identity pins conflict"
            )

        if type(self.confirmed_anchor_count) is not int or self.confirmed_anchor_count < 0:
            raise TrustedTimeHeadAnchorError(
                "trusted-time authenticated journal confirmed anchor count is invalid"
            )
        terminal = self.confirmed_anchor_tip
        first_ordinal = self.first_anchored_local_transition_ordinal
        terminal_ordinal = self.confirmed_anchor_local_transition_ordinal
        if self.confirmed_anchor_count == 0:
            if terminal is not None or first_ordinal is not None or terminal_ordinal is not None:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time authenticated journal empty anchor prefix conflicts"
                )
            return
        if type(terminal) is not TrustedTimeHeadAnchorRecord:
            raise TrustedTimeHeadAnchorError(
                "trusted-time authenticated journal confirmed tip must be exact"
            )
        terminal.__post_init__()
        if terminal.anchor_sequence != self.confirmed_anchor_count:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal confirmed sequence conflicts"
            )
        if type(first_ordinal) is not int or type(terminal_ordinal) is not int:
            raise TrustedTimeHeadAnchorError(
                "trusted-time authenticated journal anchor ordinals are invalid"
            )
        if not (1 <= first_ordinal <= terminal_ordinal <= local_count):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal anchor ordinals conflict"
            )
        terminal_pins = (
            terminal.deployment_identity_sha256,
            terminal.runtime_database_identity_sha256,
            terminal.anchor_project_identity_sha256,
            terminal.anchor_project_ref,
            terminal.bucket_name,
            terminal.principal_id,
        )
        if terminal_pins != (
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.anchor_project_ref,
            self.bucket_name,
            self.principal_id,
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal confirmed-tip identity conflicts"
            )
        if terminal_ordinal == local_count and not _anchor_record_matches_transition(
            terminal,
            self.current_transition,
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal confirmed tip conflicts with current head"
            )

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _anchor_record_matches_transition(
    record: TrustedTimeHeadAnchorRecord,
    transition: AuthenticatedTrustedTimeHeadTransition,
) -> bool:
    return (
        record.deployment_identity_sha256 == transition.deployment_identity_sha256
        and record.runtime_database_identity_sha256 == transition.runtime_database_identity_sha256
        and record.anchor_project_identity_sha256 == transition.anchor_project_identity_sha256
        and record.anchor_project_ref == transition.anchor_project_ref
        and record.bucket_name == transition.bucket_name
        and record.principal_id == transition.principal_id
        and record.head_authenticated_at_utc == transition.head_authenticated_at_utc
        and record.host_id == transition.host_id
        and record.source_id == transition.source_id
        and record.source_authority_sha256 == transition.source_authority_sha256
        and record.policy_sha256 == transition.policy_sha256
        and record.persistence_contract_version == transition.persistence_contract_version
        and record.epoch_sequence == transition.epoch_sequence
        and record.monitor_epoch_id == transition.monitor_epoch_id
        and record.epoch_sha256 == transition.epoch_sha256
        and record.evaluation_sequence == transition.evaluation_sequence
        and record.evaluation_id == transition.evaluation_id
        and record.evaluation_record_sha256 == transition.evaluation_record_sha256
        and record.state_sha256 == transition.state_sha256
        and record.probe_status == transition.probe_status
        and record.health == transition.health
        and record.reason == transition.reason
        and record.hard_failure_latched == transition.hard_failure_latched
        and record.clock_recovery_qualified == transition.clock_recovery_qualified
        and record.evaluated_at_utc == transition.evaluated_at_utc
        and record.evaluated_at_monotonic_ns == transition.evaluated_at_monotonic_ns
        and record.local_previous_host_head_sha256 == transition.previous_host_head_sha256
        and record.current_host_head_sha256 == transition.current_host_head_sha256
    )


class TrustedTimeHeadAnchorProvider(Protocol):
    """Minimal immutable-object port; adapters must not emulate no-overwrite."""

    def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity: ...

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]: ...

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]: ...

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]: ...

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes: ...

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None: ...


_PROVIDER_READBACK_EVIDENCE_SEAL = object()
_PROVIDER_READBACK_CONSUMPTION_CELL_SEAL = object()
_THREAD_LOCK_TYPE = type(threading.Lock())


class _TrustedTimeHeadAnchorProviderReadbackConsumptionCell:
    """Owner-bound atomic state shared by every reference to one proof."""

    __slots__ = ("_claim_token", "_consumed", "_evidence", "_lock", "_seal")

    _claim_token: object | None
    _consumed: bool
    _evidence: TrustedTimeHeadAnchorProviderReadbackEvidence
    _lock: LockType
    _seal: object

    def __init__(self) -> None:
        raise TypeError("trusted-time anchor provider readback consumption cells are internal")

    def _require_owner(
        self,
        evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    ) -> None:
        if (
            self._seal is not _PROVIDER_READBACK_CONSUMPTION_CELL_SEAL
            or self._evidence is not evidence
            or type(self._lock) is not _THREAD_LOCK_TYPE
            or type(self._consumed) is not bool
            or (self._claim_token is not None and type(self._claim_token) is not object)
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor provider readback consumption cell is not authentic"
            )

    def is_consumed(
        self,
        evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    ) -> bool:
        self._require_owner(evidence)
        with self._lock:
            self._require_owner(evidence)
            return self._consumed

    def claim(
        self,
        evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    ) -> object:
        self._require_owner(evidence)
        with self._lock:
            self._require_owner(evidence)
            if self._consumed or self._claim_token is not None:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time anchor provider readback evidence was already "
                    "consumed or is in use"
                )
            claim_token = object()
            self._claim_token = claim_token
            return claim_token

    def release(
        self,
        evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
        claim_token: object,
    ) -> None:
        self._require_owner(evidence)
        if type(claim_token) is not object:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor provider readback claim token is invalid"
            )
        with self._lock:
            self._require_owner(evidence)
            if self._claim_token is not claim_token or self._consumed:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time anchor provider readback claim cannot be released"
                )
            self._claim_token = None

    def consume(
        self,
        evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
        claim_token: object,
    ) -> None:
        self._require_owner(evidence)
        if type(claim_token) is not object:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor provider readback claim token is invalid"
            )
        with self._lock:
            self._require_owner(evidence)
            if self._claim_token is not claim_token or self._consumed:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time anchor provider readback claim cannot be consumed"
                )
            self._consumed = True
            self._claim_token = None


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimeHeadAnchorProviderReadbackEvidence:
    """Opaque proof that one exact object was obtained by a provider GET."""

    provider_identity: TrustedTimeHeadAnchorProviderIdentity
    bucket_name: str
    object_name: str
    anchor_intent_id: str
    anchor_intent_semantic_sha256: str
    candidate_record: TrustedTimeHeadAnchorRecord
    candidate_bytes: bytes
    candidate_bytes_sha256: str
    candidate_semantic_sha256: str
    _seal: object = field(repr=False, compare=False)
    _consumption_cell: _TrustedTimeHeadAnchorProviderReadbackConsumptionCell = field(
        repr=False,
        compare=False,
    )

    def __init__(self) -> None:
        raise TypeError(
            "TrustedTimeHeadAnchorProviderReadbackEvidence is issued by provider verification"
        )

    def __post_init__(self) -> None:
        if self._seal is not _PROVIDER_READBACK_EVIDENCE_SEAL:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor provider readback evidence is not authentic"
            )
        if type(self._consumption_cell) is not (
            _TrustedTimeHeadAnchorProviderReadbackConsumptionCell
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor provider readback consumption state is invalid"
            )
        self._consumption_cell._require_owner(self)
        if type(self.provider_identity) is not TrustedTimeHeadAnchorProviderIdentity:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor readback provider identity must be exact"
            )
        self.provider_identity.__post_init__()
        bucket = _require_bucket_name(self.bucket_name)
        object_name = _require_text(
            self.object_name,
            "trusted-time anchor readback object name",
            maximum=512,
        )
        _require_uuid(
            self.anchor_intent_id,
            "trusted-time anchor readback intent ID",
        )
        _require_sha256(
            self.anchor_intent_semantic_sha256,
            "trusted-time anchor readback intent semantic SHA-256",
        )
        if type(self.candidate_record) is not TrustedTimeHeadAnchorRecord:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor readback candidate record must be exact"
            )
        self.candidate_record.__post_init__()
        if type(self.candidate_bytes) is not bytes:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor readback candidate bytes must be exact"
            )
        byte_digest = _require_sha256(
            self.candidate_bytes_sha256,
            "trusted-time anchor readback byte SHA-256",
        )
        semantic_digest = _require_sha256(
            self.candidate_semantic_sha256,
            "trusted-time anchor readback record semantic SHA-256",
        )
        record = self.candidate_record
        prefix = trusted_time_head_anchor_object_prefix(
            deployment_identity_sha256=record.deployment_identity_sha256,
            host_id=record.host_id,
        )
        expected_name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=record.anchor_sequence,
            signed_envelope_sha256=record.byte_sha256,
        )
        expected_identity = TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=record.anchor_project_identity_sha256,
            anchor_project_ref=record.anchor_project_ref,
            principal_id=record.principal_id,
            bucket_name=record.bucket_name,
        )
        if (
            bucket != record.bucket_name
            or object_name != expected_name
            or self.provider_identity != expected_identity
            or self.candidate_bytes != record.canonical_bytes
            or byte_digest != record.byte_sha256
            or semantic_digest != record.semantic_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor provider readback evidence conflicts with its candidate"
            )

    def __copy__(self) -> TrustedTimeHeadAnchorProviderReadbackEvidence:
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
    ) -> TrustedTimeHeadAnchorProviderReadbackEvidence:
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("trusted-time anchor provider readback evidence cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[object, ...]:
        del protocol
        return self.__reduce__()

    @property
    def _consumed(self) -> bool:
        return self._consumption_cell.is_consumed(self)

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _claim_trusted_time_head_anchor_provider_readback(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
) -> object:
    if type(evidence) is not TrustedTimeHeadAnchorProviderReadbackEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider readback evidence must be exact"
        )
    evidence.__post_init__()
    return evidence._consumption_cell.claim(evidence)


def _release_trusted_time_head_anchor_provider_readback(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    claim_token: object,
) -> None:
    if type(evidence) is not TrustedTimeHeadAnchorProviderReadbackEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider readback evidence must be exact"
        )
    evidence.__post_init__()
    evidence._consumption_cell.release(evidence, claim_token)


def _consume_trusted_time_head_anchor_provider_readback(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    claim_token: object,
) -> None:
    if type(evidence) is not TrustedTimeHeadAnchorProviderReadbackEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider readback evidence must be exact"
        )
    evidence.__post_init__()
    evidence._consumption_cell.consume(evidence, claim_token)


class TrustedTimeHeadAnchorEd25519Signer(Protocol):
    """Injected private-key operation; key bytes never enter an anchor record."""

    def sign_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
    ) -> bytes: ...


class TrustedTimeHeadAnchorEd25519Verifier(Protocol):
    """Injected public-key verification independent of the object provider."""

    def verify_ed25519(
        self,
        *,
        signing_key_id: str,
        signing_public_key_sha256: str,
        payload: bytes,
        signature: bytes,
    ) -> bool: ...


_COMMITTED_INTENT_EVIDENCE_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class CommittedTrustedTimeHeadAnchorIntentEvidence:
    """Repository-issued evidence that one exact upload intent committed first."""

    intent_id: str
    committed_at_utc: datetime
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    anchor_project_ref: str
    bucket_name: str
    principal_id: str
    anchor_sequence: int
    signed_envelope_sha256: str
    semantic_sha256: str
    previous_anchor_sha256: str | None
    current_host_head_sha256: str
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    checkpoint_interval_seconds: int
    anchor_authority_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError(
            "CommittedTrustedTimeHeadAnchorIntentEvidence is issued by a durable repository"
        )

    def __post_init__(self) -> None:
        if self._seal is not _COMMITTED_INTENT_EVIDENCE_SEAL:
            raise TrustedTimeHeadAnchorError(
                "trusted-time committed anchor intent evidence is not authentic"
            )
        _require_uuid(self.intent_id, "trusted-time anchor intent ID")
        _require_utc(self.committed_at_utc, "trusted-time anchor intent commit instant")
        _require_sha256(
            self.deployment_identity_sha256,
            "trusted-time anchor intent deployment identity SHA-256",
        )
        _require_sha256(
            self.runtime_database_identity_sha256,
            "trusted-time anchor intent runtime-database identity SHA-256",
        )
        _require_sha256(
            self.anchor_project_identity_sha256,
            "trusted-time anchor intent project identity SHA-256",
        )
        _require_project_ref(self.anchor_project_ref)
        _require_bucket_name(self.bucket_name)
        _require_uuid(self.principal_id, "trusted-time anchor intent principal ID")
        sequence = _require_positive_integer(
            self.anchor_sequence,
            "trusted-time anchor intent sequence",
        )
        _require_sha256(
            self.signed_envelope_sha256,
            "trusted-time anchor intent signed-envelope SHA-256",
        )
        _require_sha256(
            self.semantic_sha256,
            "trusted-time anchor intent semantic SHA-256",
        )
        previous = _require_optional_sha256(
            self.previous_anchor_sha256,
            "trusted-time anchor intent previous-anchor SHA-256",
        )
        _require_sha256(
            self.current_host_head_sha256,
            "trusted-time anchor intent current host-head SHA-256",
        )
        if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor intent checkpoint reason must be an exact enum"
            )
        if (
            type(self.checkpoint_interval_seconds) is not int
            or self.checkpoint_interval_seconds
            != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor intent checkpoint interval must be exactly 300 seconds"
            )
        _require_sha256(
            self.anchor_authority_sha256,
            "trusted-time anchor intent authority SHA-256",
        )
        if (sequence == 1) != (previous is None):
            raise TrustedTimeHeadAnchorError(
                "trusted-time first anchor intent requires a null predecessor"
            )
        if (sequence == 1) != (
            self.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time enrollment intent is permitted only for sequence one"
            )


def _new_committed_trusted_time_head_anchor_intent_evidence(
    *,
    intent_id: str,
    committed_at_utc: datetime,
    deployment_identity_sha256: str,
    runtime_database_identity_sha256: str,
    anchor_project_identity_sha256: str,
    anchor_project_ref: str,
    bucket_name: str,
    principal_id: str,
    anchor_sequence: int,
    signed_envelope_sha256: str,
    semantic_sha256: str,
    previous_anchor_sha256: str | None,
    current_host_head_sha256: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
    """Issue evidence only after an exact durable insert/readback succeeds."""

    evidence = object.__new__(CommittedTrustedTimeHeadAnchorIntentEvidence)
    values: tuple[tuple[str, object], ...] = (
        ("intent_id", intent_id),
        ("committed_at_utc", committed_at_utc),
        ("deployment_identity_sha256", deployment_identity_sha256),
        ("runtime_database_identity_sha256", runtime_database_identity_sha256),
        ("anchor_project_identity_sha256", anchor_project_identity_sha256),
        ("anchor_project_ref", anchor_project_ref),
        ("bucket_name", bucket_name),
        ("principal_id", principal_id),
        ("anchor_sequence", anchor_sequence),
        ("signed_envelope_sha256", signed_envelope_sha256),
        ("semantic_sha256", semantic_sha256),
        ("previous_anchor_sha256", previous_anchor_sha256),
        ("current_host_head_sha256", current_host_head_sha256),
        ("checkpoint_reason", checkpoint_reason),
        ("checkpoint_interval_seconds", checkpoint_interval_seconds),
        ("anchor_authority_sha256", anchor_authority_sha256),
        ("_seal", _COMMITTED_INTENT_EVIDENCE_SEAL),
    )
    for name, value in values:
        object.__setattr__(evidence, name, value)
    evidence.__post_init__()
    return evidence


class TrustedTimeHeadAnchorIntentJournal(Protocol):
    """Durable repository port that elects one exact intent before upload."""

    def commit_trusted_time_head_anchor_intent(
        self,
        *,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    ) -> CommittedTrustedTimeHeadAnchorIntentEvidence: ...


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimeHeadAnchorReconciliationResult:
    """Successful evidence that one exact local head is remotely anchored."""

    anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...]
    local_transition_count: int
    first_anchored_local_transition_ordinal: int
    uploaded_anchor_count: int
    idempotent_duplicate_count: int
    external_head_anchor_evidence: bool

    def __init__(self) -> None:
        raise TypeError(
            "TrustedTimeHeadAnchorReconciliationResult is issued by successful reconciliation"
        )

    def __post_init__(self) -> None:
        if type(self.anchor_records) is not tuple or not self.anchor_records:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor result requires exact remote records"
            )
        if any(type(record) is not TrustedTimeHeadAnchorRecord for record in self.anchor_records):
            raise TrustedTimeHeadAnchorError("trusted-time anchor result records must be exact")
        _require_positive_integer(
            self.local_transition_count,
            "trusted-time anchor result local transition count",
        )
        first_ordinal = _require_positive_integer(
            self.first_anchored_local_transition_ordinal,
            "trusted-time first anchored local transition ordinal",
        )
        if first_ordinal > self.local_transition_count:
            raise TrustedTimeHeadAnchorError(
                "trusted-time first anchored local transition exceeds local history"
            )
        if type(self.uploaded_anchor_count) is not int or self.uploaded_anchor_count not in (0, 1):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor result upload count must be zero or one"
            )
        if (
            type(self.idempotent_duplicate_count) is not int
            or self.idempotent_duplicate_count < 0
            or self.idempotent_duplicate_count > 1
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor result duplicate count must be zero or one"
            )
        if self.uploaded_anchor_count + self.idempotent_duplicate_count > 1:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor result cannot both upload and collide"
            )
        if type(self.external_head_anchor_evidence) is not bool or not (
            self.external_head_anchor_evidence
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor result evidence must be exact true"
            )

    @property
    def current_host_head_sha256(self) -> str:
        return self.anchor_records[-1].current_host_head_sha256

    @property
    def current_anchor_sha256(self) -> str:
        """Digest of the exact terminal signed-envelope bytes."""

        return self.anchor_records[-1].byte_sha256

    @property
    def current_anchor_semantic_sha256(self) -> str:
        return self.anchor_records[-1].semantic_sha256

    @property
    def historical_local_chain_externally_authenticated(self) -> bool:
        """Enrollment/checkpoint evidence never makes this broader claim."""

        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def arming_authorized(self) -> bool:
        return False

    @property
    def exposure_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def rearm_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def automatic_resume_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


_PREPARED_RECONCILIATION_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class PreparedTrustedTimeHeadAnchorReconciliation:
    """Opaque, process-local plan prepared before a durable intent commit."""

    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...]
    confirmed_anchor_count: int
    candidate_record: TrustedTimeHeadAnchorRecord | None
    local_transition_count: int
    first_anchored_local_transition_ordinal: int
    current_host_head_sha256: str
    full_audit: bool
    bucket_name: str
    object_prefix: str
    provider_identity: TrustedTimeHeadAnchorProviderIdentity
    _provider: object = field(repr=False, compare=False)
    _verifier: object = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError("PreparedTrustedTimeHeadAnchorReconciliation is issued by preparation")

    def __post_init__(self) -> None:
        if self._seal is not _PREPARED_RECONCILIATION_SEAL:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor reconciliation plan is not authentic"
            )
        if type(self.confirmed_anchor_records) is not tuple or any(
            type(record) is not TrustedTimeHeadAnchorRecord
            for record in self.confirmed_anchor_records
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan confirmed records must be exact"
            )
        if (
            type(self.confirmed_anchor_count) is not int
            or not 0 <= self.confirmed_anchor_count <= MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE
        ):
            raise TrustedTimeHeadAnchorError("trusted-time anchor plan confirmed count is invalid")
        if (self.confirmed_anchor_count == 0) != (not self.confirmed_anchor_records):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor plan confirmed count conflicts with its retained records"
            )
        if self.confirmed_anchor_records and (
            self.confirmed_anchor_records[-1].anchor_sequence != self.confirmed_anchor_count
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor plan terminal sequence conflicts with its confirmed count"
            )
        candidate = self.candidate_record
        if candidate is not None and type(candidate) is not TrustedTimeHeadAnchorRecord:
            raise TrustedTimeHeadAnchorError("trusted-time anchor plan candidate must be exact")
        _require_positive_integer(
            self.local_transition_count,
            "trusted-time anchor plan local transition count",
        )
        ordinal = _require_positive_integer(
            self.first_anchored_local_transition_ordinal,
            "trusted-time anchor plan first anchored local transition ordinal",
        )
        if ordinal > self.local_transition_count:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan first ordinal exceeds local history"
            )
        _require_sha256(
            self.current_host_head_sha256,
            "trusted-time anchor plan current host-head SHA-256",
        )
        if type(self.full_audit) is not bool:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan full-audit flag must be exact"
            )
        _require_bucket_name(self.bucket_name)
        if type(self.provider_identity) is not TrustedTimeHeadAnchorProviderIdentity:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan provider identity must be exact"
            )
        self.provider_identity.__post_init__()
        if self.provider_identity.bucket_name != self.bucket_name:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor plan provider identity conflicts with its bucket"
            )
        _require_text(
            self.object_prefix,
            "trusted-time anchor plan object prefix",
            maximum=512,
        )
        if not self.object_prefix.endswith("/"):
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan object prefix must end with a slash"
            )
        if not self.confirmed_anchor_records and candidate is None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor plan has neither confirmed evidence nor a candidate"
            )
        if candidate is not None:
            previous = (
                None if not self.confirmed_anchor_records else self.confirmed_anchor_records[-1]
            )
            if (
                candidate.anchor_sequence != self.confirmed_anchor_count + 1
                or candidate.previous_anchor_sha256
                != (None if previous is None else previous.byte_sha256)
                or candidate.previous_anchored_host_head_sha256
                != (None if previous is None else previous.current_host_head_sha256)
                or candidate.current_host_head_sha256 != self.current_host_head_sha256
            ):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time anchor plan candidate conflicts with its confirmed prefix"
                )
        elif self.confirmed_anchor_records[-1].current_host_head_sha256 != (
            self.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time anchor plan does not terminate at the current local head"
            )


def _new_prepared_reconciliation(
    *,
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    confirmed_anchor_count: int,
    candidate_record: TrustedTimeHeadAnchorRecord | None,
    local_transition_count: int,
    first_anchored_local_transition_ordinal: int,
    current_host_head_sha256: str,
    full_audit: bool,
    bucket_name: str,
    object_prefix: str,
    provider_identity: TrustedTimeHeadAnchorProviderIdentity,
    provider: TrustedTimeHeadAnchorProvider,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    plan = object.__new__(PreparedTrustedTimeHeadAnchorReconciliation)
    object.__setattr__(plan, "confirmed_anchor_records", confirmed_anchor_records)
    object.__setattr__(plan, "confirmed_anchor_count", confirmed_anchor_count)
    object.__setattr__(plan, "candidate_record", candidate_record)
    object.__setattr__(plan, "local_transition_count", local_transition_count)
    object.__setattr__(
        plan,
        "first_anchored_local_transition_ordinal",
        first_anchored_local_transition_ordinal,
    )
    object.__setattr__(plan, "current_host_head_sha256", current_host_head_sha256)
    object.__setattr__(plan, "full_audit", full_audit)
    object.__setattr__(plan, "bucket_name", bucket_name)
    object.__setattr__(plan, "object_prefix", object_prefix)
    object.__setattr__(plan, "provider_identity", provider_identity)
    object.__setattr__(plan, "_provider", provider)
    object.__setattr__(plan, "_verifier", verifier)
    object.__setattr__(plan, "_seal", _PREPARED_RECONCILIATION_SEAL)
    plan.__post_init__()
    return plan


def _new_reconciliation_result(
    *,
    anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    local_transition_count: int,
    first_anchored_local_transition_ordinal: int,
    uploaded_anchor_count: int,
    idempotent_duplicate_count: int,
) -> TrustedTimeHeadAnchorReconciliationResult:
    result = object.__new__(TrustedTimeHeadAnchorReconciliationResult)
    object.__setattr__(result, "anchor_records", anchor_records)
    object.__setattr__(result, "local_transition_count", local_transition_count)
    object.__setattr__(
        result,
        "first_anchored_local_transition_ordinal",
        first_anchored_local_transition_ordinal,
    )
    object.__setattr__(result, "uploaded_anchor_count", uploaded_anchor_count)
    object.__setattr__(result, "idempotent_duplicate_count", idempotent_duplicate_count)
    object.__setattr__(result, "external_head_anchor_evidence", True)
    result.__post_init__()
    return result


def trusted_time_head_anchor_object_prefix(
    *,
    deployment_identity_sha256: str,
    host_id: str,
) -> str:
    """Return a safe deterministic namespace without embedding the raw host ID."""

    deployment = _require_sha256(
        deployment_identity_sha256,
        "trusted-time anchor deployment identity SHA-256",
    )
    host = _require_text(host_id, "trusted-time anchor host ID")
    host_identity_sha256 = _sha256(
        (
            TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION,
            "trusted_time_head_anchor_host_identity",
            host,
        )
    )
    return f"v1/{deployment}/{host_identity_sha256}/"


def trusted_time_head_anchor_object_name(
    *,
    prefix: str,
    anchor_sequence: int,
    signed_envelope_sha256: str,
) -> str:
    _require_text(prefix, "trusted-time anchor object prefix", maximum=512)
    if not prefix.endswith("/"):
        raise TrustedTimeHeadAnchorError("trusted-time anchor object prefix must end with a slash")
    sequence = _require_positive_integer(
        anchor_sequence,
        "trusted-time remote anchor sequence",
    )
    envelope_digest = _require_sha256(
        signed_envelope_sha256,
        "trusted-time anchor signed-envelope SHA-256",
    )
    return f"{prefix}{sequence:020d}-{envelope_digest}.json"


def _validate_local_chain(
    transitions: object,
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    if type(transitions) is not tuple or not transitions:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor reconciliation requires a complete exact local chain"
        )
    if any(type(item) is not AuthenticatedTrustedTimeHeadTransition for item in transitions):
        raise TrustedTimeHeadAnchorError("trusted-time local head transitions must be exact")
    exact = cast(tuple[AuthenticatedTrustedTimeHeadTransition, ...], transitions)
    seen_heads: set[str] = set()
    previous: AuthenticatedTrustedTimeHeadTransition | None = None
    for transition in exact:
        try:
            transition.__post_init__()
        except TrustedTimeHeadAnchorError:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorError(
                "trusted-time local head transition is invalid"
            ) from None
        if transition.current_host_head_sha256 in seen_heads:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time local authenticated chain repeats a host head"
            )
        seen_heads.add(transition.current_host_head_sha256)
        if previous is None:
            if transition.epoch_sequence != 1 or transition.evaluation_sequence != 0:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time local authenticated chain does not begin at genesis"
                )
            previous = transition
            continue
        if (
            transition.deployment_identity_sha256 != previous.deployment_identity_sha256
            or transition.runtime_database_identity_sha256
            != previous.runtime_database_identity_sha256
            or transition.anchor_project_identity_sha256 != previous.anchor_project_identity_sha256
            or transition.anchor_project_ref != previous.anchor_project_ref
            or transition.bucket_name != previous.bucket_name
            or transition.principal_id != previous.principal_id
            or transition.host_id != previous.host_id
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time local authenticated chain crosses deployment identity"
            )
        if transition.previous_host_head_sha256 != previous.current_host_head_sha256:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time local authenticated host-head predecessor conflicts"
            )
        if transition.epoch_sequence == previous.epoch_sequence:
            if (
                transition.monitor_epoch_id != previous.monitor_epoch_id
                or transition.epoch_sha256 != previous.epoch_sha256
                or transition.source_id != previous.source_id
                or transition.source_authority_sha256 != previous.source_authority_sha256
                or transition.evaluation_sequence != previous.evaluation_sequence + 1
            ):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time local evaluation chain is not gap-free within its epoch"
                )
        elif transition.epoch_sequence == previous.epoch_sequence + 1:
            if (
                transition.evaluation_sequence != 0
                or transition.monitor_epoch_id == previous.monitor_epoch_id
                or transition.epoch_sha256 == previous.epoch_sha256
            ):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time local epoch transition is malformed"
                )
        else:
            raise TrustedTimeHeadAnchorConflict("trusted-time local epoch sequence is not gap-free")
        previous = transition
    return exact


def _port_method(dependency: object, method_name: str, subject: str) -> Callable[..., object]:
    try:
        method = getattr(dependency, method_name, None)
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorError(f"trusted-time anchor {subject} is unavailable") from None
    if not callable(method):
        raise TrustedTimeHeadAnchorError(f"trusted-time anchor {subject} is unavailable")
    return cast(Callable[..., object], method)


def _read_provider_identity(
    provider: TrustedTimeHeadAnchorProvider,
) -> TrustedTimeHeadAnchorProviderIdentity:
    attest = _port_method(provider, "attest_identity", "provider identity-attestation port")
    try:
        identity = attest()
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider identity attestation failed"
        ) from None
    if type(identity) is not TrustedTimeHeadAnchorProviderIdentity:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider identity attestation must return an exact identity"
        )
    identity.__post_init__()
    return identity


def _attest_provider_identity(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    transition: AuthenticatedTrustedTimeHeadTransition,
) -> TrustedTimeHeadAnchorProviderIdentity:
    identity = _read_provider_identity(provider)
    expected = TrustedTimeHeadAnchorProviderIdentity(
        anchor_project_identity_sha256=transition.anchor_project_identity_sha256,
        anchor_project_ref=transition.anchor_project_ref,
        principal_id=transition.principal_id,
        bucket_name=transition.bucket_name,
    )
    if identity != expected:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time anchor provider identity conflicts with the authenticated local chain"
        )
    return identity


def verify_trusted_time_head_anchor_provider_readback(
    *,
    provider: TrustedTimeHeadAnchorProvider,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    anchor_intent_id: str,
    anchor_intent_semantic_sha256: str,
    record: TrustedTimeHeadAnchorRecord,
    object_name: str,
) -> TrustedTimeHeadAnchorProviderReadbackEvidence:
    """GET and seal exact provider bytes for one durably committed intent."""

    intent_id = _require_uuid(
        anchor_intent_id,
        "trusted-time anchor provider-readback intent ID",
    )
    intent_digest = _require_sha256(
        anchor_intent_semantic_sha256,
        "trusted-time anchor provider-readback intent semantic SHA-256",
    )
    if type(record) is not TrustedTimeHeadAnchorRecord:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider-readback record must be exact"
        )
    record.__post_init__()
    _verify_record(record, verifier=verifier)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=record.deployment_identity_sha256,
        host_id=record.host_id,
    )
    expected_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=record.anchor_sequence,
        signed_envelope_sha256=record.byte_sha256,
    )
    exact_name = _require_text(
        object_name,
        "trusted-time anchor provider-readback object name",
        maximum=512,
    )
    if exact_name != expected_name:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time anchor provider-readback object name conflicts"
        )
    identity = _read_provider_identity(provider)
    expected_identity = TrustedTimeHeadAnchorProviderIdentity(
        anchor_project_identity_sha256=record.anchor_project_identity_sha256,
        anchor_project_ref=record.anchor_project_ref,
        principal_id=record.principal_id,
        bucket_name=record.bucket_name,
    )
    if identity != expected_identity:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time anchor provider-readback identity conflicts"
        )
    download = _port_method(provider, "download_object", "provider download port")
    try:
        payload = download(
            bucket_name=record.bucket_name,
            object_name=exact_name,
        )
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor provider readback GET failed"
        ) from None
    if type(payload) is not bytes or payload != record.canonical_bytes:
        raise TrustedTimeHeadAnchorConflict("trusted-time anchor provider readback bytes conflict")
    downloaded = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
    if downloaded != record:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time anchor provider readback record conflicts"
        )
    _verify_record(downloaded, verifier=verifier)
    evidence = object.__new__(TrustedTimeHeadAnchorProviderReadbackEvidence)
    object.__setattr__(evidence, "provider_identity", identity)
    object.__setattr__(evidence, "bucket_name", record.bucket_name)
    object.__setattr__(evidence, "object_name", exact_name)
    object.__setattr__(evidence, "anchor_intent_id", intent_id)
    object.__setattr__(
        evidence,
        "anchor_intent_semantic_sha256",
        intent_digest,
    )
    object.__setattr__(evidence, "candidate_record", record)
    object.__setattr__(evidence, "candidate_bytes", payload)
    object.__setattr__(evidence, "candidate_bytes_sha256", record.byte_sha256)
    object.__setattr__(
        evidence,
        "candidate_semantic_sha256",
        record.semantic_sha256,
    )
    object.__setattr__(evidence, "_seal", _PROVIDER_READBACK_EVIDENCE_SEAL)
    consumption_cell = object.__new__(_TrustedTimeHeadAnchorProviderReadbackConsumptionCell)
    consumption_cell._seal = _PROVIDER_READBACK_CONSUMPTION_CELL_SEAL
    consumption_cell._evidence = evidence
    consumption_cell._lock = threading.Lock()
    consumption_cell._consumed = False
    consumption_cell._claim_token = None
    object.__setattr__(evidence, "_consumption_cell", consumption_cell)
    evidence.__post_init__()
    return evidence


def _sign_record(
    transition: AuthenticatedTrustedTimeHeadTransition,
    *,
    anchor_sequence: int,
    previous: TrustedTimeHeadAnchorRecord | None,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
    signer: TrustedTimeHeadAnchorEd25519Signer,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> TrustedTimeHeadAnchorRecord:
    semantic_material = _anchor_semantic_material(
        anchor_sequence=anchor_sequence,
        deployment_identity_sha256=transition.deployment_identity_sha256,
        runtime_database_identity_sha256=transition.runtime_database_identity_sha256,
        anchor_project_identity_sha256=transition.anchor_project_identity_sha256,
        anchor_project_ref=transition.anchor_project_ref,
        bucket_name=transition.bucket_name,
        principal_id=transition.principal_id,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=signing_public_key_sha256,
        head_authenticated_at_utc=transition.head_authenticated_at_utc,
        host_id=transition.host_id,
        source_id=transition.source_id,
        source_authority_sha256=transition.source_authority_sha256,
        policy_sha256=transition.policy_sha256,
        persistence_contract_version=transition.persistence_contract_version,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
        epoch_sequence=transition.epoch_sequence,
        monitor_epoch_id=transition.monitor_epoch_id,
        epoch_sha256=transition.epoch_sha256,
        evaluation_sequence=transition.evaluation_sequence,
        evaluation_id=transition.evaluation_id,
        evaluation_record_sha256=transition.evaluation_record_sha256,
        state_sha256=transition.state_sha256,
        probe_status=transition.probe_status,
        health=transition.health,
        reason=transition.reason,
        hard_failure_latched=transition.hard_failure_latched,
        clock_recovery_qualified=transition.clock_recovery_qualified,
        evaluated_at_utc=transition.evaluated_at_utc,
        evaluated_at_monotonic_ns=transition.evaluated_at_monotonic_ns,
        previous_anchor_sha256=None if previous is None else previous.byte_sha256,
        previous_anchored_host_head_sha256=(
            None if previous is None else previous.current_host_head_sha256
        ),
        local_previous_host_head_sha256=transition.previous_host_head_sha256,
        current_host_head_sha256=transition.current_host_head_sha256,
    )
    payload = canonical_json_bytes(semantic_material)
    sign = _port_method(signer, "sign_ed25519", "Ed25519 signer")
    try:
        signature = sign(
            signing_key_id=signing_key_id,
            signing_public_key_sha256=signing_public_key_sha256,
            payload=payload,
        )
    except Exception:
        raise TrustedTimeHeadAnchorError("trusted-time anchor Ed25519 signing failed") from None
    if type(signature) is not bytes or len(signature) != 64:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor signer returned a noncanonical Ed25519 signature"
        )
    record = TrustedTimeHeadAnchorRecord(
        anchor_sequence=anchor_sequence,
        deployment_identity_sha256=transition.deployment_identity_sha256,
        runtime_database_identity_sha256=transition.runtime_database_identity_sha256,
        anchor_project_identity_sha256=transition.anchor_project_identity_sha256,
        anchor_project_ref=transition.anchor_project_ref,
        bucket_name=transition.bucket_name,
        principal_id=transition.principal_id,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=signing_public_key_sha256,
        head_authenticated_at_utc=transition.head_authenticated_at_utc,
        host_id=transition.host_id,
        source_id=transition.source_id,
        source_authority_sha256=transition.source_authority_sha256,
        policy_sha256=transition.policy_sha256,
        persistence_contract_version=transition.persistence_contract_version,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
        epoch_sequence=transition.epoch_sequence,
        monitor_epoch_id=transition.monitor_epoch_id,
        epoch_sha256=transition.epoch_sha256,
        evaluation_sequence=transition.evaluation_sequence,
        evaluation_id=transition.evaluation_id,
        evaluation_record_sha256=transition.evaluation_record_sha256,
        state_sha256=transition.state_sha256,
        probe_status=transition.probe_status,
        health=transition.health,
        reason=transition.reason,
        hard_failure_latched=transition.hard_failure_latched,
        clock_recovery_qualified=transition.clock_recovery_qualified,
        evaluated_at_utc=transition.evaluated_at_utc,
        evaluated_at_monotonic_ns=transition.evaluated_at_monotonic_ns,
        previous_anchor_sha256=None if previous is None else previous.byte_sha256,
        previous_anchored_host_head_sha256=(
            None if previous is None else previous.current_host_head_sha256
        ),
        local_previous_host_head_sha256=transition.previous_host_head_sha256,
        current_host_head_sha256=transition.current_host_head_sha256,
        semantic_sha256=_sha256_bytes(payload),
        signature_ed25519=signature.hex(),
    )
    _verify_record(record, verifier=verifier)
    return record


def _verify_record(
    record: TrustedTimeHeadAnchorRecord,
    *,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    verify = _port_method(verifier, "verify_ed25519", "Ed25519 verifier")
    try:
        verified = verify(
            signing_key_id=record.signing_key_id,
            signing_public_key_sha256=record.signing_public_key_sha256,
            payload=record.signed_payload,
            signature=bytes.fromhex(record.signature_ed25519),
        )
    except Exception:
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor Ed25519 verification failed"
        ) from None
    if type(verified) is not bool or not verified:
        raise TrustedTimeHeadAnchorError("trusted-time remote anchor Ed25519 signature is invalid")


def _list_remote_records(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> tuple[TrustedTimeHeadAnchorRecord, ...]:
    list_names = _port_method(provider, "list_object_names", "provider list port")
    try:
        names = list_names(bucket_name=bucket_name, prefix=prefix)
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorError("trusted-time remote anchor listing failed") from None
    if type(names) is not tuple or any(type(name) is not str for name in names):
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor listing must return an exact tuple of object names"
        )
    if len(set(names)) != len(names):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor listing contains duplicate object names"
        )
    indexed_names: list[tuple[int, str, str]] = []
    for object_name in names:
        if not object_name.startswith(prefix):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor listing escaped its exact namespace"
            )
        suffix = object_name[len(prefix) :]
        match = _OBJECT_NAME.fullmatch(suffix)
        if match is None:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor object name is malformed"
            )
        sequence_text = match.group(1)
        sequence = _require_positive_integer(
            int(sequence_text),
            "trusted-time remote anchor sequence",
        )
        indexed_names.append((sequence, match.group(2), object_name))
    indexed_names.sort(key=lambda item: item[0])
    records: list[TrustedTimeHeadAnchorRecord] = []
    download = _port_method(provider, "download_object", "provider download port")
    for expected_sequence, (sequence, name_digest, object_name) in enumerate(
        indexed_names,
        start=1,
    ):
        if sequence != expected_sequence:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor sequence is not gap-free"
            )
        try:
            payload = download(bucket_name=bucket_name, object_name=object_name)
        except TrustedTimeHeadAnchorProviderUnavailable:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorError("trusted-time remote anchor download failed") from None
        if type(payload) is not bytes:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor download must return exact bytes"
            )
        record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
        if record.anchor_sequence != sequence or record.byte_sha256 != name_digest:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor object name conflicts with its signed record"
            )
        expected_name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=record.anchor_sequence,
            signed_envelope_sha256=record.byte_sha256,
        )
        if object_name != expected_name:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor object name is noncanonical"
            )
        _verify_record(record, verifier=verifier)
        records.append(record)
    return tuple(records)


@dataclass(frozen=True, slots=True)
class _BoundedRemoteAudit:
    record_count: int
    first_record: TrustedTimeHeadAnchorRecord | None
    terminal_record: TrustedTimeHeadAnchorRecord | None
    namespace_sha256: str


def _consume_remote_object_name_pages(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    consumer: Callable[[str], None],
) -> tuple[int, str]:
    """Consume one overlap-checked namespace traversal in bounded pages."""

    list_page = _port_method(
        provider,
        "list_object_names_page",
        "provider bounded-list port",
    )
    limit = TRUSTED_TIME_HEAD_ANCHOR_FULL_AUDIT_PAGE_SIZE
    offset = 0
    previous_page_terminal: str | None = None
    count = 0
    namespace_digest = hashlib.sha256()
    while True:
        try:
            raw_page = list_page(
                bucket_name=bucket_name,
                prefix=prefix,
                offset=offset,
                limit=limit,
            )
        except TrustedTimeHeadAnchorProviderUnavailable:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor bounded listing failed"
            ) from None
        if (
            type(raw_page) is not tuple
            or len(raw_page) > limit
            or any(type(name) is not str for name in raw_page)
        ):
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor bounded listing returned a malformed page"
            )
        page = cast(tuple[str, ...], raw_page)
        if len(set(page)) != len(page) or tuple(sorted(page)) != page:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor bounded listing is duplicated or unordered"
            )
        if previous_page_terminal is None:
            new_names = page
        else:
            if not page or page[0] != previous_page_terminal:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time remote anchor bounded listing drifted between pages"
                )
            new_names = page[1:]
        for object_name in new_names:
            if not object_name.startswith(prefix):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time remote anchor bounded listing escaped its namespace"
                )
            if _OBJECT_NAME.fullmatch(object_name[len(prefix) :]) is None:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time remote anchor bounded listing is contaminated"
                )
            consumer(object_name)
            namespace_digest.update(object_name.encode("ascii"))
            namespace_digest.update(b"\0")
            count += 1
            if count > TRUSTED_TIME_HEAD_ANCHOR_FULL_AUDIT_MAX_OBJECTS:
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time remote anchor bounded listing exceeded its admitted horizon"
                )
        if len(page) < limit:
            break
        previous_page_terminal = page[-1]
        offset += len(page) - 1
    return count, namespace_digest.hexdigest()


def _audit_remote_records_bounded(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    current_transition: AuthenticatedTrustedTimeHeadTransition,
    prefix: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> _BoundedRemoteAudit:
    """Authenticate a complete remote chain without retaining its history."""

    expected_sequence = 1
    previous: TrustedTimeHeadAnchorRecord | None = None
    first: TrustedTimeHeadAnchorRecord | None = None
    download = _port_method(provider, "download_object", "provider download port")

    def authenticate_object(object_name: str) -> None:
        nonlocal expected_sequence, first, previous
        suffix = object_name[len(prefix) :]
        match = _OBJECT_NAME.fullmatch(suffix)
        if match is None:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor object name is malformed"
            )
        sequence = _require_positive_integer(
            int(match.group(1)),
            "trusted-time remote anchor sequence",
        )
        if sequence != expected_sequence:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor sequence is not gap-free"
            )
        try:
            payload = download(
                bucket_name=current_transition.bucket_name,
                object_name=object_name,
            )
        except TrustedTimeHeadAnchorProviderUnavailable:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorError("trusted-time remote anchor download failed") from None
        if type(payload) is not bytes:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor download must return exact bytes"
            )
        record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
        expected_name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=record.anchor_sequence,
            signed_envelope_sha256=record.byte_sha256,
        )
        if (
            record.anchor_sequence != sequence
            or record.byte_sha256 != match.group(2)
            or object_name != expected_name
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor object name conflicts with its signed record"
            )
        _verify_record(record, verifier=verifier)
        if (
            record.deployment_identity_sha256 != current_transition.deployment_identity_sha256
            or record.runtime_database_identity_sha256
            != current_transition.runtime_database_identity_sha256
            or record.anchor_project_identity_sha256
            != current_transition.anchor_project_identity_sha256
            or record.anchor_project_ref != current_transition.anchor_project_ref
            or record.bucket_name != current_transition.bucket_name
            or record.principal_id != current_transition.principal_id
            or record.host_id != current_transition.host_id
            or record.signing_key_id != signing_key_id
            or record.signing_public_key_sha256 != signing_public_key_sha256
            or record.checkpoint_interval_seconds != checkpoint_interval_seconds
            or record.anchor_authority_sha256 != anchor_authority_sha256
            or record.previous_anchor_sha256 != (None if previous is None else previous.byte_sha256)
            or record.previous_anchored_host_head_sha256
            != (None if previous is None else previous.current_host_head_sha256)
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor bounded chain conflicts"
            )
        if first is None:
            first = record
        previous = record
        expected_sequence += 1

    count, namespace_sha256 = _consume_remote_object_name_pages(
        provider,
        bucket_name=current_transition.bucket_name,
        prefix=prefix,
        consumer=authenticate_object,
    )
    repeated_count, repeated_sha256 = _consume_remote_object_name_pages(
        provider,
        bucket_name=current_transition.bucket_name,
        prefix=prefix,
        consumer=lambda _: None,
    )
    if repeated_count != count or repeated_sha256 != namespace_sha256:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor namespace drifted during its full audit"
        )
    boundary_sequences = (1,) if count == 0 else (1, count, count + 1)
    for sequence in dict.fromkeys(boundary_sequences):
        names = _list_sequence_names(
            provider,
            bucket_name=current_transition.bucket_name,
            prefix=prefix,
            anchor_sequence=sequence,
        )
        if sequence == count + 1:
            expected_names: tuple[str, ...] = ()
        elif sequence == 1 and first is not None:
            expected_names = (
                trusted_time_head_anchor_object_name(
                    prefix=prefix,
                    anchor_sequence=first.anchor_sequence,
                    signed_envelope_sha256=first.byte_sha256,
                ),
            )
        elif sequence == count and previous is not None:
            expected_names = (
                trusted_time_head_anchor_object_name(
                    prefix=prefix,
                    anchor_sequence=previous.anchor_sequence,
                    signed_envelope_sha256=previous.byte_sha256,
                ),
            )
        else:
            expected_names = ()
        if names != expected_names:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor namespace boundary drifted during audit"
            )
    return _BoundedRemoteAudit(
        record_count=count,
        first_record=first,
        terminal_record=previous,
        namespace_sha256=namespace_sha256,
    )


def _list_sequence_names(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    anchor_sequence: int,
) -> tuple[str, ...]:
    sequence = _require_positive_integer(
        anchor_sequence,
        "trusted-time remote anchor sequence",
    )
    list_names = _port_method(
        provider,
        "list_sequence_object_names",
        "provider sequence-list port",
    )
    try:
        names = list_names(
            bucket_name=bucket_name,
            prefix=prefix,
            anchor_sequence=sequence,
        )
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor sequence listing failed"
        ) from None
    if type(names) is not tuple or any(type(name) is not str for name in names):
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor sequence listing must return an exact tuple"
        )
    if len(set(names)) != len(names):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor sequence listing contains duplicates"
        )
    for object_name in names:
        if not object_name.startswith(prefix):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor sequence listing escaped its namespace"
            )
        match = _OBJECT_NAME.fullmatch(object_name[len(prefix) :])
        if match is None or int(match.group(1)) != sequence:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor sequence listing returned a foreign sequence"
            )
    return tuple(sorted(names))


def _download_expected_record(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    record: TrustedTimeHeadAnchorRecord,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    expected_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=record.anchor_sequence,
        signed_envelope_sha256=record.byte_sha256,
    )
    download = _port_method(provider, "download_object", "provider download port")
    try:
        payload = download(bucket_name=bucket_name, object_name=expected_name)
    except TrustedTimeHeadAnchorProviderUnavailable:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time confirmed remote anchor object is absent"
        ) from None
    if type(payload) is not bytes or payload != record.canonical_bytes:
        raise TrustedTimeHeadAnchorConflict("trusted-time confirmed remote anchor bytes conflict")
    downloaded = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
    if downloaded != record:
        raise TrustedTimeHeadAnchorConflict("trusted-time confirmed remote anchor record conflicts")
    _verify_record(downloaded, verifier=verifier)


def _verify_incremental_remote_state(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    confirmed: tuple[TrustedTimeHeadAnchorRecord, ...],
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    if confirmed:
        terminal = confirmed[-1]
        terminal_names = _list_sequence_names(
            provider,
            bucket_name=bucket_name,
            prefix=prefix,
            anchor_sequence=terminal.anchor_sequence,
        )
        expected_terminal_name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=terminal.anchor_sequence,
            signed_envelope_sha256=terminal.byte_sha256,
        )
        if not terminal_names:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor history rolled back before its confirmed terminal"
            )
        if len(terminal_names) != 1 or terminal_names[0] != expected_terminal_name:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor terminal sequence contains a fork"
            )
        _download_expected_record(
            provider,
            bucket_name=bucket_name,
            prefix=prefix,
            record=terminal,
            verifier=verifier,
        )
        next_sequence = terminal.anchor_sequence + 1
    else:
        next_sequence = 1
    next_names = _list_sequence_names(
        provider,
        bucket_name=bucket_name,
        prefix=prefix,
        anchor_sequence=next_sequence,
    )
    if len(next_names) > 1:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote next anchor sequence contains multiple fork candidates"
        )
    if next_names:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history is ahead of locally confirmed evidence"
        )


def _assert_full_remote_matches_confirmed(
    remote: tuple[TrustedTimeHeadAnchorRecord, ...],
    confirmed: tuple[TrustedTimeHeadAnchorRecord, ...],
) -> None:
    if remote == confirmed:
        return
    shared_length = min(len(remote), len(confirmed))
    if remote[:shared_length] != confirmed[:shared_length]:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history forks from locally confirmed evidence"
        )
    if len(remote) < len(confirmed):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history rolled back below locally confirmed evidence"
        )
    raise TrustedTimeHeadAnchorConflict(
        "trusted-time remote anchor history is ahead of locally confirmed evidence"
    )


def _verify_recovery_remote_state(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    bucket_name: str,
    prefix: str,
    confirmed: tuple[TrustedTimeHeadAnchorRecord, ...],
    pending: TrustedTimeHeadAnchorRecord,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    """Permit only an absent or byte-exact pending object after the confirmed tip."""

    if confirmed:
        terminal = confirmed[-1]
        terminal_names = _list_sequence_names(
            provider,
            bucket_name=bucket_name,
            prefix=prefix,
            anchor_sequence=terminal.anchor_sequence,
        )
        expected_terminal = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=terminal.anchor_sequence,
            signed_envelope_sha256=terminal.byte_sha256,
        )
        if terminal_names != (expected_terminal,):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time confirmed terminal changed before pending-intent recovery"
            )
        _download_expected_record(
            provider,
            bucket_name=bucket_name,
            prefix=prefix,
            record=terminal,
            verifier=verifier,
        )
    pending_names = _list_sequence_names(
        provider,
        bucket_name=bucket_name,
        prefix=prefix,
        anchor_sequence=pending.anchor_sequence,
    )
    expected_pending = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=pending.anchor_sequence,
        signed_envelope_sha256=pending.byte_sha256,
    )
    if len(pending_names) > 1:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor sequence contains multiple fork objects"
        )
    if pending_names and pending_names != (expected_pending,):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor sequence contains a conflicting object"
        )
    if pending_names:
        _download_expected_record(
            provider,
            bucket_name=bucket_name,
            prefix=prefix,
            record=pending,
            verifier=verifier,
        )


def _assert_full_remote_allows_pending(
    remote: tuple[TrustedTimeHeadAnchorRecord, ...],
    confirmed: tuple[TrustedTimeHeadAnchorRecord, ...],
    pending: TrustedTimeHeadAnchorRecord,
) -> None:
    combined = (*confirmed, pending)
    if remote in (confirmed, combined):
        return
    shared_length = min(len(remote), len(combined))
    if remote[:shared_length] != combined[:shared_length]:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history forks from the persisted pending intent"
        )
    if len(remote) < len(confirmed):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history rolled back below confirmed evidence"
        )
    raise TrustedTimeHeadAnchorConflict(
        "trusted-time remote anchor history is ahead of the persisted pending intent"
    )


def _validate_remote_chain(
    records: tuple[TrustedTimeHeadAnchorRecord, ...],
    *,
    transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
) -> tuple[int, ...]:
    positions = {
        transition.current_host_head_sha256: index for index, transition in enumerate(transitions)
    }
    local_identity = transitions[-1]
    anchored_positions: list[int] = []
    previous: TrustedTimeHeadAnchorRecord | None = None
    for expected_sequence, record in enumerate(records, start=1):
        if type(record) is not TrustedTimeHeadAnchorRecord:
            raise TrustedTimeHeadAnchorError("trusted-time remote anchor record must be exact")
        try:
            record.__post_init__()
        except TrustedTimeHeadAnchorError:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor record is invalid"
            ) from None
        if record.anchor_sequence != expected_sequence:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor sequence is not gap-free"
            )
        if (
            record.deployment_identity_sha256 != local_identity.deployment_identity_sha256
            or record.runtime_database_identity_sha256
            != local_identity.runtime_database_identity_sha256
            or record.anchor_project_identity_sha256
            != local_identity.anchor_project_identity_sha256
            or record.anchor_project_ref != local_identity.anchor_project_ref
            or record.bucket_name != local_identity.bucket_name
            or record.principal_id != local_identity.principal_id
            or record.host_id != local_identity.host_id
            or record.signing_key_id != signing_key_id
            or record.signing_public_key_sha256 != signing_public_key_sha256
            or record.checkpoint_interval_seconds != checkpoint_interval_seconds
            or record.anchor_authority_sha256 != anchor_authority_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor crosses deployment or signing identity"
            )
        if record.previous_anchor_sha256 != (
            None if previous is None else previous.byte_sha256
        ) or record.previous_anchored_host_head_sha256 != (
            None if previous is None else previous.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote anchor predecessor chain conflicts"
            )
        position = positions.get(record.current_host_head_sha256)
        if position is None:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote head is absent from the complete authenticated local chain"
            )
        if anchored_positions and position <= anchored_positions[-1]:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote checkpoints do not advance through local history"
            )
        transition = transitions[position]
        if (
            record.head_authenticated_at_utc != transition.head_authenticated_at_utc
            or record.source_id != transition.source_id
            or record.source_authority_sha256 != transition.source_authority_sha256
            or record.policy_sha256 != transition.policy_sha256
            or record.persistence_contract_version != transition.persistence_contract_version
            or record.epoch_sequence != transition.epoch_sequence
            or record.monitor_epoch_id != transition.monitor_epoch_id
            or record.epoch_sha256 != transition.epoch_sha256
            or record.evaluation_sequence != transition.evaluation_sequence
            or record.evaluation_id != transition.evaluation_id
            or record.evaluation_record_sha256 != transition.evaluation_record_sha256
            or record.state_sha256 != transition.state_sha256
            or record.probe_status != transition.probe_status
            or record.health != transition.health
            or record.reason != transition.reason
            or record.hard_failure_latched != transition.hard_failure_latched
            or record.clock_recovery_qualified != transition.clock_recovery_qualified
            or record.evaluated_at_utc != transition.evaluated_at_utc
            or record.evaluated_at_monotonic_ns != transition.evaluated_at_monotonic_ns
            or record.local_previous_host_head_sha256 != transition.previous_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time remote checkpoint conflicts with its authenticated local head"
            )
        anchored_positions.append(position)
        previous = record
    return tuple(anchored_positions)


def _require_confirmed_records(
    value: object,
    *,
    transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> tuple[tuple[TrustedTimeHeadAnchorRecord, ...], tuple[int, ...]]:
    if type(value) is not tuple or any(
        type(record) is not TrustedTimeHeadAnchorRecord for record in value
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time locally confirmed anchor records must be an exact tuple"
        )
    records = cast(tuple[TrustedTimeHeadAnchorRecord, ...], value)
    for record in records:
        record.__post_init__()
        _verify_record(record, verifier=verifier)
    positions = _validate_remote_chain(
        records,
        transitions=transitions,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=signing_public_key_sha256,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
    )
    return records, positions


def _issue_authenticated_trusted_time_head_journal_tip(
    *,
    current_transition: AuthenticatedTrustedTimeHeadTransition,
    local_transition_count: int,
    first_local_host_head_sha256: str,
    confirmed_anchor_count: int,
    confirmed_anchor_tip: TrustedTimeHeadAnchorRecord | None,
    first_anchored_local_transition_ordinal: int | None,
    confirmed_anchor_local_transition_ordinal: int | None,
) -> AuthenticatedTrustedTimeHeadJournalTip:
    tip = object.__new__(AuthenticatedTrustedTimeHeadJournalTip)
    object.__setattr__(tip, "current_transition", current_transition)
    object.__setattr__(tip, "local_transition_count", local_transition_count)
    object.__setattr__(
        tip,
        "first_local_host_head_sha256",
        first_local_host_head_sha256,
    )
    object.__setattr__(
        tip,
        "current_local_host_head_sha256",
        current_transition.current_host_head_sha256,
    )
    object.__setattr__(tip, "confirmed_anchor_count", confirmed_anchor_count)
    object.__setattr__(tip, "confirmed_anchor_tip", confirmed_anchor_tip)
    object.__setattr__(
        tip,
        "first_anchored_local_transition_ordinal",
        first_anchored_local_transition_ordinal,
    )
    object.__setattr__(
        tip,
        "confirmed_anchor_local_transition_ordinal",
        confirmed_anchor_local_transition_ordinal,
    )
    object.__setattr__(
        tip,
        "deployment_identity_sha256",
        current_transition.deployment_identity_sha256,
    )
    object.__setattr__(
        tip,
        "runtime_database_identity_sha256",
        current_transition.runtime_database_identity_sha256,
    )
    object.__setattr__(
        tip,
        "anchor_project_identity_sha256",
        current_transition.anchor_project_identity_sha256,
    )
    object.__setattr__(tip, "anchor_project_ref", current_transition.anchor_project_ref)
    object.__setattr__(tip, "bucket_name", current_transition.bucket_name)
    object.__setattr__(tip, "principal_id", current_transition.principal_id)
    object.__setattr__(tip, "_seal", _AUTHENTICATED_JOURNAL_TIP_SEAL)
    tip.__post_init__()
    return tip


def _new_authenticated_trusted_time_head_journal_tip(
    *,
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
) -> AuthenticatedTrustedTimeHeadJournalTip:
    """Seal one completely validated startup replay into constant-size state."""

    transitions = _validate_local_chain(local_transitions)
    if type(confirmed_anchor_records) is not tuple or any(
        type(record) is not TrustedTimeHeadAnchorRecord for record in confirmed_anchor_records
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time authenticated journal confirmed records must be exact"
        )
    confirmed = confirmed_anchor_records
    positions: tuple[int, ...] = ()
    if confirmed:
        terminal = confirmed[-1]
        positions = _validate_remote_chain(
            confirmed,
            transitions=transitions,
            signing_key_id=terminal.signing_key_id,
            signing_public_key_sha256=terminal.signing_public_key_sha256,
            checkpoint_interval_seconds=terminal.checkpoint_interval_seconds,
            anchor_authority_sha256=terminal.anchor_authority_sha256,
        )
    return _issue_authenticated_trusted_time_head_journal_tip(
        current_transition=transitions[-1],
        local_transition_count=len(transitions),
        first_local_host_head_sha256=transitions[0].current_host_head_sha256,
        confirmed_anchor_count=len(confirmed),
        confirmed_anchor_tip=None if not confirmed else confirmed[-1],
        first_anchored_local_transition_ordinal=(None if not positions else positions[0] + 1),
        confirmed_anchor_local_transition_ordinal=(None if not positions else positions[-1] + 1),
    )


def _validate_authenticated_local_suffix(
    tip: AuthenticatedTrustedTimeHeadJournalTip,
    appended_local_transitions: object,
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    if type(appended_local_transitions) is not tuple or any(
        type(item) is not AuthenticatedTrustedTimeHeadTransition
        for item in appended_local_transitions
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time authenticated journal suffix must be an exact tuple"
        )
    suffix = cast(
        tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        appended_local_transitions,
    )
    previous = tip.current_transition
    seen_heads = {previous.current_host_head_sha256}
    for transition in suffix:
        transition.__post_init__()
        if transition.current_host_head_sha256 in seen_heads:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal suffix repeats a host head"
            )
        seen_heads.add(transition.current_host_head_sha256)
        if (
            transition.deployment_identity_sha256 != tip.deployment_identity_sha256
            or transition.runtime_database_identity_sha256 != tip.runtime_database_identity_sha256
            or transition.anchor_project_identity_sha256 != tip.anchor_project_identity_sha256
            or transition.anchor_project_ref != tip.anchor_project_ref
            or transition.bucket_name != tip.bucket_name
            or transition.principal_id != tip.principal_id
            or transition.host_id != previous.host_id
            or transition.previous_host_head_sha256 != previous.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal suffix identity or predecessor conflicts"
            )
        if transition.epoch_sequence == previous.epoch_sequence:
            if (
                transition.monitor_epoch_id != previous.monitor_epoch_id
                or transition.epoch_sha256 != previous.epoch_sha256
                or transition.source_id != previous.source_id
                or transition.source_authority_sha256 != previous.source_authority_sha256
                or transition.evaluation_sequence != previous.evaluation_sequence + 1
            ):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time authenticated journal evaluation suffix is not gap-free"
                )
        elif transition.epoch_sequence == previous.epoch_sequence + 1:
            if (
                transition.evaluation_sequence != 0
                or transition.monitor_epoch_id == previous.monitor_epoch_id
                or transition.epoch_sha256 == previous.epoch_sha256
            ):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time authenticated journal epoch suffix is malformed"
                )
        else:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal epoch suffix is not gap-free"
            )
        previous = transition
    return suffix


def _advance_authenticated_trusted_time_head_journal_tip(
    tip: AuthenticatedTrustedTimeHeadJournalTip,
    *,
    appended_local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    newly_confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    newly_confirmed_anchor_local_transition_ordinals: tuple[int, ...],
) -> AuthenticatedTrustedTimeHeadJournalTip:
    """Advance a sealed prefix with only authenticated local/anchor suffixes."""

    if type(tip) is not AuthenticatedTrustedTimeHeadJournalTip:
        raise TrustedTimeHeadAnchorError("trusted-time authenticated journal tip must be exact")
    tip.__post_init__()
    suffix = _validate_authenticated_local_suffix(tip, appended_local_transitions)
    if type(newly_confirmed_anchor_records) is not tuple or any(
        type(record) is not TrustedTimeHeadAnchorRecord for record in newly_confirmed_anchor_records
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time authenticated journal confirmed suffix must be exact"
        )
    if (
        type(newly_confirmed_anchor_local_transition_ordinals) is not tuple
        or len(newly_confirmed_anchor_records)
        != len(newly_confirmed_anchor_local_transition_ordinals)
        or any(
            type(ordinal) is not int for ordinal in newly_confirmed_anchor_local_transition_ordinals
        )
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time authenticated journal confirmed ordinals are invalid"
        )
    if not suffix and not newly_confirmed_anchor_records:
        return tip

    new_local_count = tip.local_transition_count + len(suffix)
    available_by_ordinal = {
        tip.local_transition_count: tip.current_transition,
        **{
            tip.local_transition_count + offset: transition
            for offset, transition in enumerate(suffix, start=1)
        },
    }
    previous_record = tip.confirmed_anchor_tip
    previous_ordinal = tip.confirmed_anchor_local_transition_ordinal
    first_ordinal = tip.first_anchored_local_transition_ordinal
    for offset, (record, ordinal) in enumerate(
        zip(
            newly_confirmed_anchor_records,
            newly_confirmed_anchor_local_transition_ordinals,
            strict=True,
        ),
        start=1,
    ):
        record.__post_init__()
        if (
            record.anchor_sequence != tip.confirmed_anchor_count + offset
            or record.previous_anchor_sha256
            != (None if previous_record is None else previous_record.byte_sha256)
            or record.previous_anchored_host_head_sha256
            != (None if previous_record is None else previous_record.current_host_head_sha256)
            or ordinal <= (0 if previous_ordinal is None else previous_ordinal)
            or ordinal > new_local_count
            or (
                record.deployment_identity_sha256,
                record.runtime_database_identity_sha256,
                record.anchor_project_identity_sha256,
                record.anchor_project_ref,
                record.bucket_name,
                record.principal_id,
            )
            != (
                tip.deployment_identity_sha256,
                tip.runtime_database_identity_sha256,
                tip.anchor_project_identity_sha256,
                tip.anchor_project_ref,
                tip.bucket_name,
                tip.principal_id,
            )
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal confirmed suffix conflicts"
            )
        available = available_by_ordinal.get(ordinal)
        if available is not None and not _anchor_record_matches_transition(
            record,
            available,
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time authenticated journal confirmed suffix head conflicts"
            )
        previous_record = record
        previous_ordinal = ordinal
        if first_ordinal is None:
            first_ordinal = ordinal

    return _issue_authenticated_trusted_time_head_journal_tip(
        current_transition=(tip.current_transition if not suffix else suffix[-1]),
        local_transition_count=new_local_count,
        first_local_host_head_sha256=tip.first_local_host_head_sha256,
        confirmed_anchor_count=(tip.confirmed_anchor_count + len(newly_confirmed_anchor_records)),
        confirmed_anchor_tip=previous_record,
        first_anchored_local_transition_ordinal=first_ordinal,
        confirmed_anchor_local_transition_ordinal=previous_ordinal,
    )


def prepare_trusted_time_head_anchor_reconciliation(
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    *,
    provider: TrustedTimeHeadAnchorProvider,
    signer: TrustedTimeHeadAnchorEd25519Signer,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    pending_anchor_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None,
    full_audit: bool,
    allow_enrollment: bool = False,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    """Verify local/remote state and prepare at most one signed checkpoint.

    ``full_audit=True`` is the explicit startup path and traverses the complete
    namespace once.  ``full_audit=False`` is the constant-work periodic path:
    it authenticates the confirmed terminal object and enumerates only its
    exact sequence plus the exact next sequence.  This function never uploads.
    """

    if type(full_audit) is not bool:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor full-audit flag must be an exact boolean"
        )
    if type(allow_enrollment) is not bool:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor enrollment permission must be an exact boolean"
        )
    if pending_anchor_intent is not None:
        if type(pending_anchor_intent) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
            raise TrustedTimeHeadAnchorError("trusted-time pending anchor intent must be exact")
        pending_anchor_intent.__post_init__()
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor intent must be recovered before preparing a successor"
        )
    if type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor checkpoint reason must be an exact enum"
        )
    if (
        type(checkpoint_interval_seconds) is not int
        or checkpoint_interval_seconds != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor checkpoint interval must be exactly 300 seconds"
        )
    authority_sha256 = _require_sha256(
        anchor_authority_sha256,
        "trusted-time anchor authority SHA-256",
    )
    transitions = _validate_local_chain(local_transitions)
    key_id = _require_text(signing_key_id, "trusted-time anchor signing-key ID")
    public_key_sha256 = _require_sha256(
        signing_public_key_sha256,
        "trusted-time anchor signing public-key SHA-256",
    )
    current = transitions[-1]
    provider_identity = _attest_provider_identity(provider, transition=current)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=current.deployment_identity_sha256,
        host_id=current.host_id,
    )
    confirmed, confirmed_positions = _require_confirmed_records(
        confirmed_anchor_records,
        transitions=transitions,
        signing_key_id=key_id,
        signing_public_key_sha256=public_key_sha256,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=authority_sha256,
        verifier=verifier,
    )
    if full_audit:
        remote = _list_remote_records(
            provider,
            bucket_name=current.bucket_name,
            prefix=prefix,
            verifier=verifier,
        )
        _validate_remote_chain(
            remote,
            transitions=transitions,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            checkpoint_interval_seconds=checkpoint_interval_seconds,
            anchor_authority_sha256=authority_sha256,
        )
        _assert_full_remote_matches_confirmed(remote, confirmed)
    else:
        _verify_incremental_remote_state(
            provider,
            bucket_name=current.bucket_name,
            prefix=prefix,
            confirmed=confirmed,
            verifier=verifier,
        )
    if not confirmed and not allow_enrollment:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history is absent and enrollment is not approved"
        )
    if (not confirmed) != (checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time enrollment checkpoint reason is permitted only for first enrollment"
        )

    candidate: TrustedTimeHeadAnchorRecord | None = None
    if not confirmed or confirmed[-1].current_host_head_sha256 != (
        current.current_host_head_sha256
    ):
        candidate = _sign_record(
            current,
            anchor_sequence=len(confirmed) + 1,
            previous=None if not confirmed else confirmed[-1],
            checkpoint_reason=checkpoint_reason,
            checkpoint_interval_seconds=checkpoint_interval_seconds,
            anchor_authority_sha256=authority_sha256,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            signer=signer,
            verifier=verifier,
        )
    first_ordinal = len(transitions) if not confirmed_positions else confirmed_positions[0] + 1
    return _new_prepared_reconciliation(
        confirmed_anchor_records=confirmed,
        confirmed_anchor_count=len(confirmed),
        candidate_record=candidate,
        local_transition_count=len(transitions),
        first_anchored_local_transition_ordinal=first_ordinal,
        current_host_head_sha256=current.current_host_head_sha256,
        full_audit=full_audit,
        bucket_name=current.bucket_name,
        object_prefix=prefix,
        provider_identity=provider_identity,
        provider=provider,
        verifier=verifier,
    )


def prepare_bounded_trusted_time_head_anchor_reconciliation(
    authenticated_journal_tip: AuthenticatedTrustedTimeHeadJournalTip,
    *,
    provider: TrustedTimeHeadAnchorProvider,
    signer: TrustedTimeHeadAnchorEd25519Signer,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    pending_anchor_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None,
    allow_enrollment: bool,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    """Prepare from constant-size durable tips after a bounded full remote audit."""

    if type(authenticated_journal_tip) is not AuthenticatedTrustedTimeHeadJournalTip:
        raise TrustedTimeHeadAnchorError(
            "trusted-time bounded reconciliation requires an authenticated journal tip"
        )
    authenticated_journal_tip.__post_init__()
    if pending_anchor_intent is not None:
        if type(pending_anchor_intent) is CommittedTrustedTimeHeadAnchorIntentEvidence:
            pending_anchor_intent.__post_init__()
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor intent must be recovered before preparing a successor"
        )
    if type(allow_enrollment) is not bool:
        raise TrustedTimeHeadAnchorError("trusted-time bounded enrollment permission must be exact")
    if type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
        raise TrustedTimeHeadAnchorError("trusted-time bounded checkpoint reason must be exact")
    if (
        type(checkpoint_interval_seconds) is not int
        or checkpoint_interval_seconds != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor checkpoint interval must be exactly 300 seconds"
        )
    authority_sha256 = _require_sha256(
        anchor_authority_sha256,
        "trusted-time anchor authority SHA-256",
    )
    key_id = _require_text(signing_key_id, "trusted-time anchor signing-key ID")
    public_key_sha256 = _require_sha256(
        signing_public_key_sha256,
        "trusted-time anchor signing public-key SHA-256",
    )
    tip = authenticated_journal_tip
    current = tip.current_transition
    provider_identity = _attest_provider_identity(provider, transition=current)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=current.deployment_identity_sha256,
        host_id=current.host_id,
    )
    remote = _audit_remote_records_bounded(
        provider,
        current_transition=current,
        prefix=prefix,
        signing_key_id=key_id,
        signing_public_key_sha256=public_key_sha256,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=authority_sha256,
        verifier=verifier,
    )
    terminal = tip.confirmed_anchor_tip
    if remote.record_count != tip.confirmed_anchor_count or (remote.terminal_record != terminal):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time bounded remote audit conflicts with durable confirmed evidence"
        )
    if (terminal is None) != (tip.confirmed_anchor_count == 0):
        raise TrustedTimeHeadAnchorConflict("trusted-time durable confirmed terminal is incomplete")
    if terminal is not None:
        terminal.__post_init__()
        _verify_record(terminal, verifier=verifier)
        if (
            terminal.signing_key_id != key_id
            or terminal.signing_public_key_sha256 != public_key_sha256
            or terminal.checkpoint_interval_seconds != checkpoint_interval_seconds
            or terminal.anchor_authority_sha256 != authority_sha256
        ):
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time durable confirmed terminal crosses admitted authority"
            )
    if terminal is None and not allow_enrollment:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time remote anchor history is absent and enrollment is not approved"
        )
    if (terminal is None) != (
        checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
    ):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time enrollment checkpoint reason is permitted only for first enrollment"
        )
    candidate: TrustedTimeHeadAnchorRecord | None = None
    if terminal is None or terminal.current_host_head_sha256 != (current.current_host_head_sha256):
        candidate = _sign_record(
            current,
            anchor_sequence=tip.confirmed_anchor_count + 1,
            previous=terminal,
            checkpoint_reason=checkpoint_reason,
            checkpoint_interval_seconds=checkpoint_interval_seconds,
            anchor_authority_sha256=authority_sha256,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            signer=signer,
            verifier=verifier,
        )
    first_ordinal = (
        tip.local_transition_count
        if terminal is None
        else tip.first_anchored_local_transition_ordinal
    )
    if type(first_ordinal) is not int:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time bounded confirmed prefix lacks its first local ordinal"
        )
    return _new_prepared_reconciliation(
        confirmed_anchor_records=() if terminal is None else (terminal,),
        confirmed_anchor_count=tip.confirmed_anchor_count,
        candidate_record=candidate,
        local_transition_count=tip.local_transition_count,
        first_anchored_local_transition_ordinal=first_ordinal,
        current_host_head_sha256=current.current_host_head_sha256,
        full_audit=True,
        bucket_name=current.bucket_name,
        object_prefix=prefix,
        provider_identity=provider_identity,
        provider=provider,
        verifier=verifier,
    )


def prepare_incremental_trusted_time_head_anchor_reconciliation(
    authenticated_journal_tip: AuthenticatedTrustedTimeHeadJournalTip,
    *,
    provider: TrustedTimeHeadAnchorProvider,
    signer: TrustedTimeHeadAnchorEd25519Signer,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    pending_anchor_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    """Prepare one constant-size checkpoint from a repository-issued tip.

    This path is admitted only after a complete startup replay has been sealed
    into ``authenticated_journal_tip``.  It retains the confirmed terminal
    record, verifies that exact remote sequence and the exact next sequence,
    and signs at most the current authenticated local head.  It never lists a
    complete namespace, opens enrollment, recovers a pending intent, or
    accepts a caller-constructed trust root.
    """

    if type(authenticated_journal_tip) is not AuthenticatedTrustedTimeHeadJournalTip:
        raise TrustedTimeHeadAnchorError(
            "trusted-time incremental reconciliation requires an authenticated journal tip"
        )
    authenticated_journal_tip.__post_init__()
    if pending_anchor_intent is not None:
        if type(pending_anchor_intent) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
            raise TrustedTimeHeadAnchorError("trusted-time pending anchor intent must be exact")
        pending_anchor_intent.__post_init__()
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor intent must be recovered before preparing a successor"
        )
    if type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
        raise TrustedTimeHeadAnchorError(
            "trusted-time incremental checkpoint reason must be an exact enum"
        )
    if checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time enrollment requires the explicit full startup path"
        )
    if (
        type(checkpoint_interval_seconds) is not int
        or checkpoint_interval_seconds != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    ):
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor checkpoint interval must be exactly 300 seconds"
        )
    authority_sha256 = _require_sha256(
        anchor_authority_sha256,
        "trusted-time anchor authority SHA-256",
    )
    key_id = _require_text(signing_key_id, "trusted-time anchor signing-key ID")
    public_key_sha256 = _require_sha256(
        signing_public_key_sha256,
        "trusted-time anchor signing public-key SHA-256",
    )
    current = authenticated_journal_tip.current_transition
    terminal = authenticated_journal_tip.confirmed_anchor_tip
    if terminal is None or authenticated_journal_tip.confirmed_anchor_count == 0:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time incremental reconciliation requires prior enrollment"
        )
    terminal.__post_init__()
    _verify_record(terminal, verifier=verifier)
    if (
        terminal.anchor_sequence != authenticated_journal_tip.confirmed_anchor_count
        or terminal.signing_key_id != key_id
        or terminal.signing_public_key_sha256 != public_key_sha256
        or terminal.checkpoint_interval_seconds != checkpoint_interval_seconds
        or terminal.anchor_authority_sha256 != authority_sha256
    ):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time incremental confirmed terminal conflicts with admitted authority"
        )
    provider_identity = _attest_provider_identity(provider, transition=current)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=current.deployment_identity_sha256,
        host_id=current.host_id,
    )
    confirmed = (terminal,)
    _verify_incremental_remote_state(
        provider,
        bucket_name=current.bucket_name,
        prefix=prefix,
        confirmed=confirmed,
        verifier=verifier,
    )
    candidate: TrustedTimeHeadAnchorRecord | None = None
    if terminal.current_host_head_sha256 != current.current_host_head_sha256:
        candidate = _sign_record(
            current,
            anchor_sequence=authenticated_journal_tip.confirmed_anchor_count + 1,
            previous=terminal,
            checkpoint_reason=checkpoint_reason,
            checkpoint_interval_seconds=checkpoint_interval_seconds,
            anchor_authority_sha256=authority_sha256,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            signer=signer,
            verifier=verifier,
        )
    first_ordinal = authenticated_journal_tip.first_anchored_local_transition_ordinal
    if type(first_ordinal) is not int:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time incremental confirmed prefix lacks its first local ordinal"
        )
    return _new_prepared_reconciliation(
        confirmed_anchor_records=confirmed,
        confirmed_anchor_count=authenticated_journal_tip.confirmed_anchor_count,
        candidate_record=candidate,
        local_transition_count=authenticated_journal_tip.local_transition_count,
        first_anchored_local_transition_ordinal=first_ordinal,
        current_host_head_sha256=current.current_host_head_sha256,
        full_audit=False,
        bucket_name=current.bucket_name,
        object_prefix=prefix,
        provider_identity=provider_identity,
        provider=provider,
        verifier=verifier,
    )


def prepare_persisted_trusted_time_head_anchor_intent_recovery(
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    *,
    pending_record: TrustedTimeHeadAnchorRecord,
    committed_intent: CommittedTrustedTimeHeadAnchorIntentEvidence,
    provider: TrustedTimeHeadAnchorProvider,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    full_audit: bool,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    """Rebuild a completion plan for one exact intent persisted before a crash.

    Recovery never invokes a signer and never advances beyond the persisted
    candidate.  Later authenticated local transitions are allowed; callers
    must recover this pending anchor before signing a successor anchor.
    """

    if type(full_audit) is not bool:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor recovery full-audit flag must be an exact boolean"
        )
    if type(pending_record) is not TrustedTimeHeadAnchorRecord:
        raise TrustedTimeHeadAnchorError("trusted-time pending anchor record must be exact")
    if type(committed_intent) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time pending anchor recovery requires exact committed-intent evidence"
        )
    transitions = _validate_local_chain(local_transitions)
    key_id = _require_text(signing_key_id, "trusted-time anchor signing-key ID")
    public_key_sha256 = _require_sha256(
        signing_public_key_sha256,
        "trusted-time anchor signing public-key SHA-256",
    )
    pending_record.__post_init__()
    _verify_record(pending_record, verifier=verifier)
    committed_intent.__post_init__()
    current = transitions[-1]
    provider_identity = _attest_provider_identity(provider, transition=current)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=current.deployment_identity_sha256,
        host_id=current.host_id,
    )
    confirmed, _ = _require_confirmed_records(
        confirmed_anchor_records,
        transitions=transitions,
        signing_key_id=key_id,
        signing_public_key_sha256=public_key_sha256,
        checkpoint_interval_seconds=pending_record.checkpoint_interval_seconds,
        anchor_authority_sha256=pending_record.anchor_authority_sha256,
        verifier=verifier,
    )
    combined = (*confirmed, pending_record)
    positions = _validate_remote_chain(
        combined,
        transitions=transitions,
        signing_key_id=key_id,
        signing_public_key_sha256=public_key_sha256,
        checkpoint_interval_seconds=pending_record.checkpoint_interval_seconds,
        anchor_authority_sha256=pending_record.anchor_authority_sha256,
    )
    if pending_record.anchor_sequence != len(confirmed) + 1:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time pending anchor does not immediately follow the confirmed tip"
        )
    plan = _new_prepared_reconciliation(
        confirmed_anchor_records=confirmed,
        confirmed_anchor_count=len(confirmed),
        candidate_record=pending_record,
        local_transition_count=len(transitions),
        first_anchored_local_transition_ordinal=positions[0] + 1,
        current_host_head_sha256=pending_record.current_host_head_sha256,
        full_audit=full_audit,
        bucket_name=current.bucket_name,
        object_prefix=prefix,
        provider_identity=provider_identity,
        provider=provider,
        verifier=verifier,
    )
    _require_committed_intent(plan, committed_intent)
    if full_audit:
        remote = _list_remote_records(
            provider,
            bucket_name=current.bucket_name,
            prefix=prefix,
            verifier=verifier,
        )
        _validate_remote_chain(
            remote,
            transitions=transitions,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            checkpoint_interval_seconds=pending_record.checkpoint_interval_seconds,
            anchor_authority_sha256=pending_record.anchor_authority_sha256,
        )
        _assert_full_remote_allows_pending(remote, confirmed, pending_record)
    else:
        _verify_recovery_remote_state(
            provider,
            bucket_name=current.bucket_name,
            prefix=prefix,
            confirmed=confirmed,
            pending=pending_record,
            verifier=verifier,
        )
    return plan


def prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery(
    authenticated_journal_tip: AuthenticatedTrustedTimeHeadJournalTip,
    *,
    pending_record: TrustedTimeHeadAnchorRecord,
    pending_local_transition_ordinal: int,
    committed_intent: CommittedTrustedTimeHeadAnchorIntentEvidence,
    provider: TrustedTimeHeadAnchorProvider,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    full_audit: bool,
) -> PreparedTrustedTimeHeadAnchorReconciliation:
    """Recover one durable pending intent from compact tips and bounded remote I/O."""

    if type(authenticated_journal_tip) is not AuthenticatedTrustedTimeHeadJournalTip:
        raise TrustedTimeHeadAnchorError(
            "trusted-time bounded recovery requires an authenticated journal tip"
        )
    authenticated_journal_tip.__post_init__()
    if type(full_audit) is not bool:
        raise TrustedTimeHeadAnchorError(
            "trusted-time bounded recovery full-audit flag must be exact"
        )
    if type(pending_record) is not TrustedTimeHeadAnchorRecord:
        raise TrustedTimeHeadAnchorError("trusted-time bounded pending record must be exact")
    if type(committed_intent) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time bounded recovery requires exact committed-intent evidence"
        )
    pending_ordinal = _require_positive_integer(
        pending_local_transition_ordinal,
        "trusted-time bounded pending local transition ordinal",
    )
    tip = authenticated_journal_tip
    if pending_ordinal > tip.local_transition_count:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time bounded pending ordinal exceeds local history"
        )
    key_id = _require_text(signing_key_id, "trusted-time anchor signing-key ID")
    public_key_sha256 = _require_sha256(
        signing_public_key_sha256,
        "trusted-time anchor signing public-key SHA-256",
    )
    pending_record.__post_init__()
    _verify_record(pending_record, verifier=verifier)
    committed_intent.__post_init__()
    current = tip.current_transition
    terminal = tip.confirmed_anchor_tip
    if (
        pending_record.anchor_sequence != tip.confirmed_anchor_count + 1
        or pending_record.deployment_identity_sha256 != tip.deployment_identity_sha256
        or pending_record.runtime_database_identity_sha256 != tip.runtime_database_identity_sha256
        or pending_record.anchor_project_identity_sha256 != tip.anchor_project_identity_sha256
        or pending_record.anchor_project_ref != tip.anchor_project_ref
        or pending_record.bucket_name != tip.bucket_name
        or pending_record.principal_id != tip.principal_id
        or pending_record.host_id != current.host_id
        or pending_record.signing_key_id != key_id
        or pending_record.signing_public_key_sha256 != public_key_sha256
        or pending_record.previous_anchor_sha256
        != (None if terminal is None else terminal.byte_sha256)
        or pending_record.previous_anchored_host_head_sha256
        != (None if terminal is None else terminal.current_host_head_sha256)
        or (
            tip.confirmed_anchor_local_transition_ordinal is not None
            and pending_ordinal <= tip.confirmed_anchor_local_transition_ordinal
        )
    ):
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time bounded pending intent conflicts with durable tips"
        )
    provider_identity = _attest_provider_identity(provider, transition=current)
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=current.deployment_identity_sha256,
        host_id=current.host_id,
    )
    confirmed = () if terminal is None else (terminal,)
    first_ordinal = (
        pending_ordinal if terminal is None else tip.first_anchored_local_transition_ordinal
    )
    if type(first_ordinal) is not int:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time bounded recovery lacks its first local ordinal"
        )
    plan = _new_prepared_reconciliation(
        confirmed_anchor_records=confirmed,
        confirmed_anchor_count=tip.confirmed_anchor_count,
        candidate_record=pending_record,
        local_transition_count=tip.local_transition_count,
        first_anchored_local_transition_ordinal=first_ordinal,
        current_host_head_sha256=pending_record.current_host_head_sha256,
        full_audit=full_audit,
        bucket_name=current.bucket_name,
        object_prefix=prefix,
        provider_identity=provider_identity,
        provider=provider,
        verifier=verifier,
    )
    _require_committed_intent(plan, committed_intent)
    if full_audit:
        remote = _audit_remote_records_bounded(
            provider,
            current_transition=current,
            prefix=prefix,
            signing_key_id=key_id,
            signing_public_key_sha256=public_key_sha256,
            checkpoint_interval_seconds=pending_record.checkpoint_interval_seconds,
            anchor_authority_sha256=pending_record.anchor_authority_sha256,
            verifier=verifier,
        )
        allowed = (
            (tip.confirmed_anchor_count, terminal),
            (tip.confirmed_anchor_count + 1, pending_record),
        )
        if (remote.record_count, remote.terminal_record) not in allowed:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time bounded remote audit conflicts with its pending intent"
            )
    else:
        _verify_recovery_remote_state(
            provider,
            bucket_name=current.bucket_name,
            prefix=prefix,
            confirmed=confirmed,
            pending=pending_record,
            verifier=verifier,
        )
    return plan


def _complete_candidate_upload(
    provider: TrustedTimeHeadAnchorProvider,
    *,
    record: TrustedTimeHeadAnchorRecord,
    prefix: str,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> tuple[int, int]:
    """Upload/re-read one sequence candidate without traversing the archive."""

    object_name = trusted_time_head_anchor_object_name(
        prefix=prefix,
        anchor_sequence=record.anchor_sequence,
        signed_envelope_sha256=record.byte_sha256,
    )
    names = _list_sequence_names(
        provider,
        bucket_name=record.bucket_name,
        prefix=prefix,
        anchor_sequence=record.anchor_sequence,
    )
    if len(names) > 1:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time candidate sequence contains multiple fork objects"
        )
    if names:
        if names[0] != object_name:
            raise TrustedTimeHeadAnchorConflict(
                "trusted-time candidate sequence contains a conflicting object"
            )
        _download_expected_record(
            provider,
            bucket_name=record.bucket_name,
            prefix=prefix,
            record=record,
            verifier=verifier,
        )
        return 0, 1

    upload = _port_method(provider, "upload_object_no_overwrite", "provider upload port")
    upload_error: Exception | None = None
    try:
        returned = upload(
            bucket_name=record.bucket_name,
            object_name=object_name,
            payload=record.canonical_bytes,
            content_type=TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
        )
        if returned is not None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor upload port must return exact null"
            )
    except TrustedTimeHeadAnchorProviderUnavailable as error:
        upload_error = error
    except TrustedTimeHeadAnchorError:
        raise
    except Exception as error:
        upload_error = error

    names = _list_sequence_names(
        provider,
        bucket_name=record.bucket_name,
        prefix=prefix,
        anchor_sequence=record.anchor_sequence,
    )
    if len(names) != 1 or names[0] != object_name:
        if isinstance(upload_error, TrustedTimeHeadAnchorProviderUnavailable):
            raise upload_error
        if upload_error is not None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor upload failed without an exact candidate"
            ) from upload_error
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time uploaded sequence does not contain exactly its candidate"
        )
    _download_expected_record(
        provider,
        bucket_name=record.bucket_name,
        prefix=prefix,
        record=record,
        verifier=verifier,
    )
    return (0, 1) if upload_error is not None else (1, 0)


def _require_committed_intent(
    prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    evidence: CommittedTrustedTimeHeadAnchorIntentEvidence | None,
) -> None:
    candidate = prepared.candidate_record
    if candidate is None:
        if evidence is not None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor completion received intent evidence without a candidate"
            )
        return
    if type(evidence) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor candidate requires exact committed-intent evidence"
        )
    evidence.__post_init__()
    expected = (
        candidate.deployment_identity_sha256,
        candidate.runtime_database_identity_sha256,
        candidate.anchor_project_identity_sha256,
        candidate.anchor_project_ref,
        candidate.bucket_name,
        candidate.principal_id,
        candidate.anchor_sequence,
        candidate.byte_sha256,
        candidate.semantic_sha256,
        candidate.previous_anchor_sha256,
        candidate.current_host_head_sha256,
        candidate.checkpoint_reason,
        candidate.checkpoint_interval_seconds,
        candidate.anchor_authority_sha256,
    )
    actual = (
        evidence.deployment_identity_sha256,
        evidence.runtime_database_identity_sha256,
        evidence.anchor_project_identity_sha256,
        evidence.anchor_project_ref,
        evidence.bucket_name,
        evidence.principal_id,
        evidence.anchor_sequence,
        evidence.signed_envelope_sha256,
        evidence.semantic_sha256,
        evidence.previous_anchor_sha256,
        evidence.current_host_head_sha256,
        evidence.checkpoint_reason,
        evidence.checkpoint_interval_seconds,
        evidence.anchor_authority_sha256,
    )
    if actual != expected:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time committed anchor intent conflicts with the prepared candidate"
        )


def complete_trusted_time_head_anchor_reconciliation(
    prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    *,
    provider: TrustedTimeHeadAnchorProvider,
    committed_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None,
) -> TrustedTimeHeadAnchorReconciliationResult:
    """Complete one authenticated plan after its exact intent commits durably."""

    if type(prepared) is not PreparedTrustedTimeHeadAnchorReconciliation:
        raise TrustedTimeHeadAnchorError(
            "trusted-time anchor prepared reconciliation must be exact"
        )
    prepared.__post_init__()
    if provider is not prepared._provider:
        raise TrustedTimeHeadAnchorError("trusted-time anchor completion crossed provider identity")
    if _read_provider_identity(provider) != prepared.provider_identity:
        raise TrustedTimeHeadAnchorConflict(
            "trusted-time anchor provider identity changed before completion"
        )
    _require_committed_intent(prepared, committed_intent)
    verifier = cast(TrustedTimeHeadAnchorEd25519Verifier, prepared._verifier)
    candidate = prepared.candidate_record
    uploaded_count = 0
    duplicate_count = 0
    final_records = prepared.confirmed_anchor_records
    if candidate is not None:
        if prepared.confirmed_anchor_records:
            terminal = prepared.confirmed_anchor_records[-1]
            terminal_names = _list_sequence_names(
                provider,
                bucket_name=prepared.bucket_name,
                prefix=prepared.object_prefix,
                anchor_sequence=terminal.anchor_sequence,
            )
            expected_terminal_name = trusted_time_head_anchor_object_name(
                prefix=prepared.object_prefix,
                anchor_sequence=terminal.anchor_sequence,
                signed_envelope_sha256=terminal.byte_sha256,
            )
            if terminal_names != (expected_terminal_name,):
                raise TrustedTimeHeadAnchorConflict(
                    "trusted-time confirmed terminal changed before completion"
                )
            _download_expected_record(
                provider,
                bucket_name=prepared.bucket_name,
                prefix=prepared.object_prefix,
                record=terminal,
                verifier=verifier,
            )
        uploaded_count, duplicate_count = _complete_candidate_upload(
            provider,
            record=candidate,
            prefix=prepared.object_prefix,
            verifier=verifier,
        )
        final_records = (*prepared.confirmed_anchor_records, candidate)
    return _new_reconciliation_result(
        anchor_records=final_records,
        local_transition_count=prepared.local_transition_count,
        first_anchored_local_transition_ordinal=(prepared.first_anchored_local_transition_ordinal),
        uploaded_anchor_count=uploaded_count,
        idempotent_duplicate_count=duplicate_count,
    )


def reconcile_trusted_time_head_anchors(
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...] = (),
    *,
    provider: TrustedTimeHeadAnchorProvider,
    signer: TrustedTimeHeadAnchorEd25519Signer,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    signing_key_id: str,
    signing_public_key_sha256: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    intent_journal: TrustedTimeHeadAnchorIntentJournal | None,
    pending_anchor_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None = None,
    full_audit: bool = True,
    allow_enrollment: bool = False,
) -> TrustedTimeHeadAnchorReconciliationResult:
    """Compatibility composition; production should persist between its two phases."""

    prepared = prepare_trusted_time_head_anchor_reconciliation(
        local_transitions,
        confirmed_anchor_records,
        provider=provider,
        signer=signer,
        verifier=verifier,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=signing_public_key_sha256,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
        pending_anchor_intent=pending_anchor_intent,
        full_audit=full_audit,
        allow_enrollment=allow_enrollment,
    )
    committed_intent: CommittedTrustedTimeHeadAnchorIntentEvidence | None = None
    if prepared.candidate_record is not None:
        if intent_journal is None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor candidate requires a durable intent journal"
            )
        commit = _port_method(
            intent_journal,
            "commit_trusted_time_head_anchor_intent",
            "intent-journal commit port",
        )
        try:
            committed = commit(prepared=prepared)
        except Exception:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor durable intent commit failed"
            ) from None
        if type(committed) is not CommittedTrustedTimeHeadAnchorIntentEvidence:
            raise TrustedTimeHeadAnchorError(
                "trusted-time anchor intent journal returned noncanonical evidence"
            )
        committed_intent = committed
    return complete_trusted_time_head_anchor_reconciliation(
        prepared,
        provider=provider,
        committed_intent=committed_intent,
    )


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TrustedTimeHeadAnchorError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _decode_canonical_typed_json(payload: str) -> object:
    try:
        parsed = cast(
            object,
            json.loads(payload, object_pairs_hook=_unique_json_object),
        )
    except (json.JSONDecodeError, RecursionError):
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor payload is not valid JSON"
        ) from None
    return _decode_typed_node(parsed)


def _decode_typed_node(node: object, *, depth: int = 0) -> object:
    if depth > 4:
        raise TrustedTimeHeadAnchorError("trusted-time remote anchor canonical nesting is too deep")
    if type(node) is not dict:
        raise TrustedTimeHeadAnchorError("trusted-time remote anchor canonical node is malformed")
    values = cast(dict[str, object], node)
    node_type = values.get("type")
    if node_type == "enum":
        if set(values) != {"enum_type", "type", "value"}:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical enum has unexpected fields"
            )
        enum_type = _expect_string(values["enum_type"], "canonical enum type")
        decoded_value = _decode_typed_node(values["value"], depth=depth + 1)
        if type(decoded_value) is not str:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical enum value must be text"
            )
        supported_enums = {
            f"{TrustedTimeProbeStatus.__module__}.{TrustedTimeProbeStatus.__qualname__}": (
                TrustedTimeProbeStatus
            ),
            f"{TrustedTimeHealth.__module__}.{TrustedTimeHealth.__qualname__}": (TrustedTimeHealth),
            f"{TrustedTimeReason.__module__}.{TrustedTimeReason.__qualname__}": (TrustedTimeReason),
        }
        enum_class = supported_enums.get(enum_type)
        if enum_class is None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical enum type is unsupported"
            )
        try:
            return enum_class(decoded_value)
        except ValueError:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical enum value is unsupported"
            ) from None
    if set(values) != {"type", "value"}:
        raise TrustedTimeHeadAnchorError(
            "trusted-time remote anchor canonical node has unexpected fields"
        )
    value = values["value"]
    if node_type == "null":
        if value is not None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical null is malformed"
            )
        return None
    if node_type == "string":
        return _expect_string(value, "canonical string")
    if node_type == "bool":
        if type(value) is not bool:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical boolean is malformed"
            )
        return value
    if node_type == "int":
        raw = _expect_string(value, "canonical integer")
        if _CANONICAL_INTEGER.fullmatch(raw) is None:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical integer is malformed"
            )
        return int(raw)
    if node_type == "datetime":
        raw = _expect_string(value, "canonical datetime")
        if not raw.endswith("Z"):
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical datetime must use UTC Z form"
            )
        try:
            instant = datetime.fromisoformat(f"{raw[:-1]}+00:00")
        except ValueError:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical datetime is malformed"
            ) from None
        return _require_utc(instant, "trusted-time remote anchor canonical datetime")
    if node_type == "tuple":
        if type(value) is not list:
            raise TrustedTimeHeadAnchorError(
                "trusted-time remote anchor canonical tuple is malformed"
            )
        return tuple(_decode_typed_node(item, depth=depth + 1) for item in value)
    raise TrustedTimeHeadAnchorError(
        "trusted-time remote anchor canonical node type is unsupported"
    )


def _expect_tuple(value: object, field_name: str, *, size: int) -> tuple[object, ...]:
    if type(value) is not tuple or len(value) != size:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be an exact {size}-item tuple")
    return cast(tuple[object, ...], value)


def _expect_string(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be exact text")
    return value


def _expect_optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _expect_string(value, field_name)


def _expect_optional_probe_status(value: object) -> TrustedTimeProbeStatus | None:
    if value is None:
        return None
    raw = _expect_string(value, "probe status")
    try:
        return TrustedTimeProbeStatus(raw)
    except ValueError:
        raise TrustedTimeHeadAnchorError("probe status is unsupported") from None


def _expect_optional_health(value: object) -> TrustedTimeHealth | None:
    if value is None:
        return None
    raw = _expect_string(value, "health")
    try:
        return TrustedTimeHealth(raw)
    except ValueError:
        raise TrustedTimeHeadAnchorError("health is unsupported") from None


def _expect_optional_reason(value: object) -> TrustedTimeReason | None:
    if value is None:
        return None
    raw = _expect_string(value, "reason")
    try:
        return TrustedTimeReason(raw)
    except ValueError:
        raise TrustedTimeHeadAnchorError("reason is unsupported") from None


def _expect_checkpoint_reason(value: object) -> TrustedTimeHeadAnchorCheckpointReason:
    raw = _expect_string(value, "checkpoint reason")
    try:
        return TrustedTimeHeadAnchorCheckpointReason(raw)
    except ValueError:
        raise TrustedTimeHeadAnchorError("checkpoint reason is unsupported") from None


def _expect_optional_boolean(value: object, field_name: str) -> bool | None:
    if value is None:
        return None
    if type(value) is not bool:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be an exact boolean")
    return value


def _expect_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be an exact integer")
    return value


def _expect_optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _expect_integer(value, field_name)


def _expect_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise TrustedTimeHeadAnchorError(f"{field_name} must be an exact datetime")
    return value


def _expect_optional_datetime(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _expect_datetime(value, field_name)
