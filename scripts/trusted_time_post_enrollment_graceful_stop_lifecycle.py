"""Dormant durable lifecycle records for one future graceful-stop attempt.

The fixed attempt slot is also journal ordinal zero.  Later records are
immutable, predecessor-linked recovery evidence.  This module deliberately
cannot represent a signal attempt, a post-signal fact, or a confirmed stop.
Its state registry is closure-private; its capability-sealed writer seams are
module-private and have no production caller.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple, Never, cast
from weakref import WeakKeyDictionary

from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES,
    TrustedTimePostEnrollmentGracefulStopDecision,
    canonical_post_enrollment_graceful_stop_decision_bytes,
    decode_post_enrollment_graceful_stop_decision,
)
from scripts.trusted_time_post_enrollment_shutdown_locator import (
    POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES,
    TrustedTimePostEnrollmentGracefulStopShutdownLocator,
    decode_post_enrollment_graceful_stop_shutdown_locator,
)

POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-attempt-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-progress-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_TRANSCRIPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-progress-transcript-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-retained-outcome-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-lifecycle"
)
POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_STATUS = "graceful_stop_attempt_reserved"
POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STATUS = "operation_bound_supervisor_bridge_required"
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS = "recovery_required"
POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON = (
    "operation_bound_supervisor_bridge_unavailable"
)

POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME = ".post-enrollment-graceful-stop-attempt-slot"
POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME = (
    ".post-enrollment-graceful-stop-progress-staging"
)
POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX = (
    "trusted-time-post-enrollment-graceful-stop-progress-01-"
)
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME = (
    ".post-enrollment-graceful-stop-outcome-staging"
)
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_PREFIX = (
    "trusted-time-post-enrollment-graceful-stop-outcome-"
)
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_SUFFIX = ".json"
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME = (
    ".post-enrollment-graceful-stop-outcome-commit-staging"
)
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME = (
    ".post-enrollment-graceful-stop-outcome-committed"
)
POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-outcome-commit-v1"
)

MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES = (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
    + POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES
    + 64 * 1_024
)
MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES = 32 * 1_024
MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES = 32 * 1_024
MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_ENTRIES = 64
MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_FILE_NAME_BYTES = 255

_MAXIMUM_JSON_DEPTH = 32
_MAXIMUM_JSON_NODES = 8_192
_MAXIMUM_JSON_INTEGER_BITS = 256
_PROCESS_LOCK = threading.RLock()
_CONSTRUCTION_CAPABILITY = object()

_LIFECYCLE_FALSE_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        "automatic_recovery_authorized",
        "clean_stop_terminal_authenticated",
        "graceful_stop_confirmed",
        "operation_bound_supervisor_bridge_authenticated",
        "post_signal_state_authenticated",
        "progress_retention_authorized",
        "provider_terminal_observed_under_stable_sql_authenticated",
        "recovery_action_authorized",
        "signal_attempted",
        "terminal_outcome_success_confirmed",
        "teardown_authenticated",
    }
)

_ATTEMPT_FIELDS = frozenset(
    {
        *_LIFECYCLE_FALSE_FIELDS,
        "attempt_slot_reserved",
        "contract_version",
        "controller_outcome_sha256",
        "durable_recovery_checkpoint",
        "durable_shutdown_locator",
        "durable_shutdown_locator_sha256",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "operator_attestation_envelope",
        "operator_attestation_envelope_sha256",
        "operator_attestation_signature_sha256",
        "operator_attestation_statement_sha256",
        "operator_authority_artifact_sha256",
        "operator_public_key_sha256",
        "phase",
        "predecessor_record_sha256",
        "progress_ordinal",
        "recovery_required_if_terminal",
        "service",
        "start_approval_sha256",
        "start_execution_attempt_slot_sha256",
        "start_operation_id",
        "start_operator_attestation_envelope_sha256",
        "status",
    }
)
_PROGRESS_FIELDS = frozenset(
    {
        *_LIFECYCLE_FALSE_FIELDS,
        "attempt_slot_reserved",
        "attempt_slot_sha256",
        "contract_version",
        "durable_recovery_checkpoint",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "operation_bound_supervisor_bridge_available",
        "operator_attestation_envelope_sha256",
        "phase",
        "predecessor_record_sha256",
        "progress_ordinal",
        "recovery_required_if_terminal",
        "service",
        "status",
    }
)
_OUTCOME_FIELDS = frozenset(
    {
        *_LIFECYCLE_FALSE_FIELDS,
        "attempt_slot_reserved",
        "attempt_slot_sha256",
        "contract_version",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "latest_progress_phase",
        "latest_progress_record_sha256",
        "operator_attestation_envelope_sha256",
        "progress_ordinal",
        "progress_transcript_sha256",
        "qualified",
        "reason",
        "recovery_required",
        "retry_authorized",
        "service",
        "status",
        "terminal_outcome_retained",
    }
)


class TrustedTimePostEnrollmentGracefulStopProgressPhase(StrEnum):
    """The only two representable pre-signal lifecycle phases."""

    ATTEMPT_RESERVED = "attempt_reserved"
    OPERATION_BOUND_SUPERVISOR_BRIDGE_REQUIRED = "operation_bound_supervisor_bridge_required"


class TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus(StrEnum):
    """Read-only durable-state classification; never continuation authority."""

    UNRESERVED = "unreserved"
    RECOVERY_REQUIRED = "recovery_required"
    TERMINAL_OUTCOME_RETAINED = "terminal_outcome_retained"
    RETENTION_UNCONFIRMED = "retention_unconfirmed"


class TrustedTimePostEnrollmentGracefulStopLifecycleRejected(RuntimeError):
    """Canonical evidence or a process-private lifecycle transition was rejected."""


class TrustedTimePostEnrollmentGracefulStopAttemptConsumed(RuntimeError):
    """The fixed attempt root exists or may exist and is never retryable."""


class TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(RuntimeError):
    """A durable write may have begun, so later mutation is forbidden."""


class TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(RuntimeError):
    """Exact retained lifecycle evidence could not be loaded or revalidated."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _bounded_json_integer(token: str) -> int:
    if len(token) > 80:
        raise ValueError
    value = int(token)
    if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
        raise ValueError
    return value


def _reject_float(_: str) -> Never:
    raise ValueError


def _bounded_tree(value: object) -> None:
    remaining = _MAXIMUM_JSON_NODES
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > _MAXIMUM_JSON_DEPTH:
            raise ValueError
        if item is None or type(item) in {bool, int}:
            continue
        if type(item) is str:
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError
            continue
        if type(item) is list:
            stack.extend((child, depth + 1) for child in cast(list[object], item))
            continue
        if type(item) is dict:
            mapping = cast(dict[object, object], item)
            if any(type(key) is not str for key in mapping):
                raise ValueError
            stack.extend((child, depth + 1) for child in mapping.values())
            continue
        raise ValueError


def _decode_canonical_object(encoded: object, *, maximum_bytes: int) -> dict[str, object]:
    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > maximum_bytes
        or not encoded.endswith(b"\n")
        or encoded.count(b"\n") != 1
    ):
        raise ValueError
    payload = json.loads(
        encoded,
        object_pairs_hook=_unique_json_object,
        parse_int=_bounded_json_integer,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )
    _bounded_tree(payload)
    if type(payload) is not dict or canonical_first_enrollment_json_bytes(payload) != encoded:
        raise ValueError
    return cast(dict[str, object], payload)


def _decode_canonical_base64(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str:
        raise ValueError
    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value or (
        exact_length is not None and len(decoded) != exact_length
    ):
        raise ValueError
    return decoded


def _false_payload() -> dict[str, object]:
    return {field_name: False for field_name in _LIFECYCLE_FALSE_FIELDS}


def _cannot_copy() -> Never:
    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
        "trusted-time graceful-stop lifecycle evidence cannot be copied or serialized"
    )


class _ValidatedAttemptRecordProjection(NamedTuple):
    envelope: TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope
    locator: TrustedTimePostEnrollmentGracefulStopShutdownLocator
    envelope_payload: dict[str, object]
    locator_payload: dict[str, object]


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimePostEnrollmentGracefulStopAttemptRecord:
    """Canonical ordinal-zero operation root; never stop authority."""

    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    operator_attestation_envelope_sha256: str
    operator_attestation_statement_sha256: str
    operator_attestation_signature_sha256: str
    operator_authority_artifact_sha256: str
    operator_public_key_sha256: str
    controller_outcome_sha256: str
    durable_shutdown_locator_sha256: str
    start_operation_id: str
    start_approval_sha256: str
    start_execution_attempt_slot_sha256: str
    start_operator_attestation_envelope_sha256: str
    _envelope_encoded: bytes = field(repr=False)
    _locator_encoded: bytes = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        operator_attestation_envelope_sha256: str,
        operator_attestation_statement_sha256: str,
        operator_attestation_signature_sha256: str,
        operator_authority_artifact_sha256: str,
        operator_public_key_sha256: str,
        controller_outcome_sha256: str,
        durable_shutdown_locator_sha256: str,
        start_operation_id: str,
        start_approval_sha256: str,
        start_execution_attempt_slot_sha256: str,
        start_operator_attestation_envelope_sha256: str,
        envelope_encoded: bytes,
        locator_encoded: bytes,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop attempt record must be decoded or issued"
            )
        values = {
            "graceful_stop_operation_id": graceful_stop_operation_id,
            "graceful_stop_target_sha256": graceful_stop_target_sha256,
            "graceful_stop_decision_v1_sha256": graceful_stop_decision_v1_sha256,
            "operator_attestation_envelope_sha256": operator_attestation_envelope_sha256,
            "operator_attestation_statement_sha256": operator_attestation_statement_sha256,
            "operator_attestation_signature_sha256": operator_attestation_signature_sha256,
            "operator_authority_artifact_sha256": operator_authority_artifact_sha256,
            "operator_public_key_sha256": operator_public_key_sha256,
            "controller_outcome_sha256": controller_outcome_sha256,
            "durable_shutdown_locator_sha256": durable_shutdown_locator_sha256,
            "start_operation_id": start_operation_id,
            "start_approval_sha256": start_approval_sha256,
            "start_execution_attempt_slot_sha256": start_execution_attempt_slot_sha256,
            "start_operator_attestation_envelope_sha256": (
                start_operator_attestation_envelope_sha256
            ),
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_envelope_encoded", envelope_encoded)
        object.__setattr__(self, "_locator_encoded", locator_encoded)
        object.__setattr__(self, "_sealed_fields", self._seal_values())
        self.__post_init__()

    def _seal_values(self) -> tuple[object, ...]:
        return (
            self.graceful_stop_operation_id,
            self.graceful_stop_target_sha256,
            self.graceful_stop_decision_v1_sha256,
            self.operator_attestation_envelope_sha256,
            self.operator_attestation_statement_sha256,
            self.operator_attestation_signature_sha256,
            self.operator_authority_artifact_sha256,
            self.operator_public_key_sha256,
            self.controller_outcome_sha256,
            self.durable_shutdown_locator_sha256,
            self.start_operation_id,
            self.start_approval_sha256,
            self.start_execution_attempt_slot_sha256,
            self.start_operator_attestation_envelope_sha256,
            self._envelope_encoded,
            self._locator_encoded,
        )

    def _validated_projection(self) -> _ValidatedAttemptRecordProjection:
        try:
            if (
                type(self) is not TrustedTimePostEnrollmentGracefulStopAttemptRecord
                or type(self._sealed_fields) is not tuple
            ):
                raise ValueError
            envelope = decode_post_enrollment_graceful_stop_operator_attestation_envelope(
                self._envelope_encoded
            )
            envelope_payload = _decode_canonical_object(
                self._envelope_encoded,
                maximum_bytes=(
                    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
                ),
            )
            decision_encoded = _decode_canonical_base64(
                envelope_payload["graceful_stop_decision_v1_base64"]
            )
            decision = decode_post_enrollment_graceful_stop_decision(decision_encoded)
            decision_payload = _decode_canonical_object(
                decision_encoded,
                maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES,
            )
            target_encoded = _nested_encoded(decision_payload["graceful_stop_target"])
            target_payload = cast(dict[str, object], decision_payload["graceful_stop_target"])
            target_locator_encoded = _nested_encoded(target_payload["durable_shutdown_locator"])
            locator = decode_post_enrollment_graceful_stop_shutdown_locator(self._locator_encoded)
            locator_payload = _decode_canonical_object(
                self._locator_encoded,
                maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES,
            )
            statement_payload = cast(
                dict[str, object],
                envelope_payload["operator_attestation_statement"],
            )
            statement_encoded = _nested_encoded(statement_payload)
            signature = _decode_canonical_base64(
                envelope_payload["signature_base64"],
                exact_length=64,
            )
            sha_values = (
                self.graceful_stop_target_sha256,
                self.graceful_stop_decision_v1_sha256,
                self.operator_attestation_envelope_sha256,
                self.operator_attestation_statement_sha256,
                self.operator_attestation_signature_sha256,
                self.operator_authority_artifact_sha256,
                self.operator_public_key_sha256,
                self.controller_outcome_sha256,
                self.durable_shutdown_locator_sha256,
                self.start_approval_sha256,
                self.start_execution_attempt_slot_sha256,
                self.start_operator_attestation_envelope_sha256,
            )
            if (
                not _is_uuid4(self.graceful_stop_operation_id)
                or not _is_uuid4(self.start_operation_id)
                or not all(_is_sha256(value) for value in sha_values)
                or decision.operation_id != self.graceful_stop_operation_id
                or hashlib.sha256(decision_encoded).hexdigest()
                != self.graceful_stop_decision_v1_sha256
                or hashlib.sha256(target_encoded).hexdigest() != self.graceful_stop_target_sha256
                or hashlib.sha256(self._envelope_encoded).hexdigest()
                != self.operator_attestation_envelope_sha256
                or hashlib.sha256(statement_encoded).hexdigest()
                != self.operator_attestation_statement_sha256
                or hashlib.sha256(signature).hexdigest()
                != self.operator_attestation_signature_sha256
                or statement_payload["authority_artifact_sha256"]
                != self.operator_authority_artifact_sha256
                or statement_payload["public_key_sha256"] != self.operator_public_key_sha256
                or target_payload["controller_outcome_sha256"] != self.controller_outcome_sha256
                or target_payload["durable_shutdown_locator_sha256"]
                != self.durable_shutdown_locator_sha256
                or target_payload["start_operation_id"] != self.start_operation_id
                or target_payload["start_approval_sha256"] != self.start_approval_sha256
                or target_payload["start_execution_attempt_slot_sha256"]
                != self.start_execution_attempt_slot_sha256
                or target_payload["start_operator_attestation_envelope_sha256"]
                != self.start_operator_attestation_envelope_sha256
                or target_locator_encoded != self._locator_encoded
                or hashlib.sha256(self._locator_encoded).hexdigest()
                != self.durable_shutdown_locator_sha256
                or self._seal_values() != self._sealed_fields
            ):
                raise ValueError
            return _ValidatedAttemptRecordProjection(
                envelope=envelope,
                locator=locator,
                envelope_payload=envelope_payload,
                locator_payload=locator_payload,
            )
        except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop attempt record is invalid"
            ) from None

    def __post_init__(self) -> None:
        self._validated_projection()

    @property
    def envelope(self) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
        return self._validated_projection().envelope

    @property
    def durable_shutdown_locator(
        self,
    ) -> TrustedTimePostEnrollmentGracefulStopShutdownLocator:
        return self._validated_projection().locator

    def _payload_from_nested(
        self,
        *,
        envelope_payload: dict[str, object],
        locator_payload: dict[str, object],
    ) -> dict[str, object]:
        payload = _false_payload()
        payload.update(
            {
                "attempt_slot_reserved": True,
                "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_CONTRACT_VERSION,
                "controller_outcome_sha256": self.controller_outcome_sha256,
                "durable_recovery_checkpoint": True,
                "durable_shutdown_locator": locator_payload,
                "durable_shutdown_locator_sha256": self.durable_shutdown_locator_sha256,
                "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
                "graceful_stop_operation_id": self.graceful_stop_operation_id,
                "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
                "operator_attestation_envelope": envelope_payload,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "operator_attestation_signature_sha256": (
                    self.operator_attestation_signature_sha256
                ),
                "operator_attestation_statement_sha256": (
                    self.operator_attestation_statement_sha256
                ),
                "operator_authority_artifact_sha256": self.operator_authority_artifact_sha256,
                "operator_public_key_sha256": self.operator_public_key_sha256,
                "phase": TrustedTimePostEnrollmentGracefulStopProgressPhase.ATTEMPT_RESERVED,
                "predecessor_record_sha256": None,
                "progress_ordinal": 0,
                "recovery_required_if_terminal": True,
                "service": POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE,
                "start_approval_sha256": self.start_approval_sha256,
                "start_execution_attempt_slot_sha256": (self.start_execution_attempt_slot_sha256),
                "start_operation_id": self.start_operation_id,
                "start_operator_attestation_envelope_sha256": (
                    self.start_operator_attestation_envelope_sha256
                ),
                "status": POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_STATUS,
            }
        )
        return payload

    def payload(self) -> dict[str, object]:
        projection = self._validated_projection()
        return self._payload_from_nested(
            envelope_payload=projection.envelope_payload,
            locator_payload=projection.locator_payload,
        )

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_attempt_bytes(self)

    @property
    def record_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimePostEnrollmentGracefulStopProgressRecord:
    """The sole pre-signal checkpoint: an operation-bound bridge is absent."""

    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    operator_attestation_envelope_sha256: str
    attempt_slot_sha256: str
    predecessor_record_sha256: str
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        operator_attestation_envelope_sha256: str,
        attempt_slot_sha256: str,
        predecessor_record_sha256: str,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop progress record must be decoded or issued"
            )
        values = (
            graceful_stop_operation_id,
            graceful_stop_target_sha256,
            graceful_stop_decision_v1_sha256,
            operator_attestation_envelope_sha256,
            attempt_slot_sha256,
            predecessor_record_sha256,
        )
        for name, value in zip(
            (
                "graceful_stop_operation_id",
                "graceful_stop_target_sha256",
                "graceful_stop_decision_v1_sha256",
                "operator_attestation_envelope_sha256",
                "attempt_slot_sha256",
                "predecessor_record_sha256",
            ),
            values,
            strict=True,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopProgressRecord
            or type(self._sealed_fields) is not tuple
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop progress record is invalid"
            )
        values = (
            self.graceful_stop_target_sha256,
            self.graceful_stop_decision_v1_sha256,
            self.operator_attestation_envelope_sha256,
            self.attempt_slot_sha256,
            self.predecessor_record_sha256,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopProgressRecord
            or not _is_uuid4(self.graceful_stop_operation_id)
            or not all(_is_sha256(value) for value in values)
            or self.attempt_slot_sha256 != self.predecessor_record_sha256
            or self._sealed_fields
            != (
                self.graceful_stop_operation_id,
                self.graceful_stop_target_sha256,
                self.graceful_stop_decision_v1_sha256,
                self.operator_attestation_envelope_sha256,
                self.attempt_slot_sha256,
                self.predecessor_record_sha256,
            )
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop progress record is invalid"
            )

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _false_payload()
        payload.update(
            {
                "attempt_slot_reserved": True,
                "attempt_slot_sha256": self.attempt_slot_sha256,
                "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_CONTRACT_VERSION,
                "durable_recovery_checkpoint": True,
                "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
                "graceful_stop_operation_id": self.graceful_stop_operation_id,
                "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
                "operation_bound_supervisor_bridge_available": False,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "phase": (
                    TrustedTimePostEnrollmentGracefulStopProgressPhase.OPERATION_BOUND_SUPERVISOR_BRIDGE_REQUIRED
                ),
                "predecessor_record_sha256": self.predecessor_record_sha256,
                "progress_ordinal": 1,
                "recovery_required_if_terminal": True,
                "service": POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE,
                "status": POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STATUS,
            }
        )
        return payload

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_progress_bytes(self)

    @property
    def record_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


def _progress_transcript_sha256(attempt_sha256: str, progress_sha256: str) -> str:
    if not _is_sha256(attempt_sha256) or not _is_sha256(progress_sha256):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress transcript is invalid"
        )
    return hashlib.sha256(
        canonical_first_enrollment_json_bytes(
            {
                "attempt_slot_sha256": attempt_sha256,
                "contract_version": (
                    POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_TRANSCRIPT_CONTRACT_VERSION
                ),
                "progress_record_count": 1,
                "progress_record_ordinals": [1],
                "progress_record_sha256s": [progress_sha256],
                "service": POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE,
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimePostEnrollmentGracefulStopOutcomeRecord:
    """Recovery-only terminal projection; confirmed shutdown is unrepresentable."""

    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    operator_attestation_envelope_sha256: str
    attempt_slot_sha256: str
    latest_progress_record_sha256: str
    progress_transcript_sha256: str
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        operator_attestation_envelope_sha256: str,
        attempt_slot_sha256: str,
        latest_progress_record_sha256: str,
        progress_transcript_sha256: str,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop outcome record must be decoded or issued"
            )
        values = (
            graceful_stop_operation_id,
            graceful_stop_target_sha256,
            graceful_stop_decision_v1_sha256,
            operator_attestation_envelope_sha256,
            attempt_slot_sha256,
            latest_progress_record_sha256,
            progress_transcript_sha256,
        )
        for name, value in zip(
            (
                "graceful_stop_operation_id",
                "graceful_stop_target_sha256",
                "graceful_stop_decision_v1_sha256",
                "operator_attestation_envelope_sha256",
                "attempt_slot_sha256",
                "latest_progress_record_sha256",
                "progress_transcript_sha256",
            ),
            values,
            strict=True,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOutcomeRecord
            or type(self._sealed_fields) is not tuple
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop outcome record is invalid"
            )
        digests = (
            self.graceful_stop_target_sha256,
            self.graceful_stop_decision_v1_sha256,
            self.operator_attestation_envelope_sha256,
            self.attempt_slot_sha256,
            self.latest_progress_record_sha256,
            self.progress_transcript_sha256,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOutcomeRecord
            or not _is_uuid4(self.graceful_stop_operation_id)
            or not all(_is_sha256(value) for value in digests)
            or self.progress_transcript_sha256
            != _progress_transcript_sha256(
                self.attempt_slot_sha256,
                self.latest_progress_record_sha256,
            )
            or self._sealed_fields
            != (
                self.graceful_stop_operation_id,
                self.graceful_stop_target_sha256,
                self.graceful_stop_decision_v1_sha256,
                self.operator_attestation_envelope_sha256,
                self.attempt_slot_sha256,
                self.latest_progress_record_sha256,
                self.progress_transcript_sha256,
            )
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop outcome record is invalid"
            )

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _false_payload()
        payload.update(
            {
                "attempt_slot_reserved": True,
                "attempt_slot_sha256": self.attempt_slot_sha256,
                "contract_version": (
                    POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_CONTRACT_VERSION
                ),
                "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
                "graceful_stop_operation_id": self.graceful_stop_operation_id,
                "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
                "latest_progress_phase": (
                    TrustedTimePostEnrollmentGracefulStopProgressPhase.OPERATION_BOUND_SUPERVISOR_BRIDGE_REQUIRED
                ),
                "latest_progress_record_sha256": self.latest_progress_record_sha256,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "progress_ordinal": 1,
                "progress_transcript_sha256": self.progress_transcript_sha256,
                "qualified": False,
                "reason": POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON,
                "recovery_required": True,
                "retry_authorized": False,
                "service": POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE,
                "status": POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS,
                "terminal_outcome_retained": True,
            }
        )
        return payload

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_outcome_bytes(self)

    @property
    def record_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


def canonical_post_enrollment_graceful_stop_attempt_bytes(record: object) -> bytes:
    if type(record) is not TrustedTimePostEnrollmentGracefulStopAttemptRecord:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt record is invalid"
        )
    encoded = canonical_first_enrollment_json_bytes(record.payload())
    if len(encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt record is invalid"
        )
    return encoded


def canonical_post_enrollment_graceful_stop_progress_bytes(record: object) -> bytes:
    if type(record) is not TrustedTimePostEnrollmentGracefulStopProgressRecord:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress record is invalid"
        )
    record.__post_init__()
    encoded = canonical_first_enrollment_json_bytes(record.payload())
    if len(encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress record is invalid"
        )
    return encoded


def canonical_post_enrollment_graceful_stop_outcome_bytes(record: object) -> bytes:
    if type(record) is not TrustedTimePostEnrollmentGracefulStopOutcomeRecord:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome record is invalid"
        )
    record.__post_init__()
    encoded = canonical_first_enrollment_json_bytes(record.payload())
    if len(encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome record is invalid"
        )
    return encoded


def _nested_encoded(value: object) -> bytes:
    if type(value) is not dict:
        raise ValueError
    return canonical_first_enrollment_json_bytes(value)


def _decode_post_enrollment_graceful_stop_attempt_material(
    encoded: object,
) -> tuple[TrustedTimePostEnrollmentGracefulStopAttemptRecord, str]:
    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
        )
        if set(payload) != _ATTEMPT_FIELDS:
            raise ValueError
        if any(payload[field_name] is not False for field_name in _LIFECYCLE_FALSE_FIELDS):
            raise ValueError
        if (
            payload["attempt_slot_reserved"] is not True
            or payload["durable_recovery_checkpoint"] is not True
            or payload["recovery_required_if_terminal"] is not True
            or payload["contract_version"] != POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_CONTRACT_VERSION
            or payload["service"] != POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE
            or payload["status"] != POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_STATUS
            or payload["phase"]
            != TrustedTimePostEnrollmentGracefulStopProgressPhase.ATTEMPT_RESERVED
            or type(payload["progress_ordinal"]) is not int
            or payload["progress_ordinal"] != 0
            or payload["predecessor_record_sha256"] is not None
        ):
            raise ValueError
        envelope_encoded = _nested_encoded(payload["operator_attestation_envelope"])
        locator_encoded = _nested_encoded(payload["durable_shutdown_locator"])
        record = TrustedTimePostEnrollmentGracefulStopAttemptRecord(
            graceful_stop_operation_id=cast(str, payload["graceful_stop_operation_id"]),
            graceful_stop_target_sha256=cast(str, payload["graceful_stop_target_sha256"]),
            graceful_stop_decision_v1_sha256=cast(str, payload["graceful_stop_decision_v1_sha256"]),
            operator_attestation_envelope_sha256=cast(
                str, payload["operator_attestation_envelope_sha256"]
            ),
            operator_attestation_statement_sha256=cast(
                str, payload["operator_attestation_statement_sha256"]
            ),
            operator_attestation_signature_sha256=cast(
                str, payload["operator_attestation_signature_sha256"]
            ),
            operator_authority_artifact_sha256=cast(
                str, payload["operator_authority_artifact_sha256"]
            ),
            operator_public_key_sha256=cast(str, payload["operator_public_key_sha256"]),
            controller_outcome_sha256=cast(str, payload["controller_outcome_sha256"]),
            durable_shutdown_locator_sha256=cast(str, payload["durable_shutdown_locator_sha256"]),
            start_operation_id=cast(str, payload["start_operation_id"]),
            start_approval_sha256=cast(str, payload["start_approval_sha256"]),
            start_execution_attempt_slot_sha256=cast(
                str, payload["start_execution_attempt_slot_sha256"]
            ),
            start_operator_attestation_envelope_sha256=cast(
                str, payload["start_operator_attestation_envelope_sha256"]
            ),
            envelope_encoded=envelope_encoded,
            locator_encoded=locator_encoded,
            _construction_capability=_CONSTRUCTION_CAPABILITY,
        )
        record_payload = record._payload_from_nested(
            envelope_payload=cast(dict[str, object], payload["operator_attestation_envelope"]),
            locator_payload=cast(dict[str, object], payload["durable_shutdown_locator"]),
        )
        record_encoded = canonical_first_enrollment_json_bytes(record_payload)
        if record_payload != payload or record_encoded != encoded:
            raise ValueError
        return record, hashlib.sha256(record_encoded).hexdigest()
    except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt record is invalid"
        ) from None


def decode_post_enrollment_graceful_stop_attempt_bytes(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopAttemptRecord:
    return _decode_post_enrollment_graceful_stop_attempt_material(encoded)[0]


def decode_post_enrollment_graceful_stop_progress_bytes(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopProgressRecord:
    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
        )
        if set(payload) != _PROGRESS_FIELDS:
            raise ValueError
        if any(payload[field_name] is not False for field_name in _LIFECYCLE_FALSE_FIELDS):
            raise ValueError
        if (
            payload["attempt_slot_reserved"] is not True
            or payload["durable_recovery_checkpoint"] is not True
            or payload["recovery_required_if_terminal"] is not True
            or payload["operation_bound_supervisor_bridge_available"] is not False
            or payload["contract_version"]
            != POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_CONTRACT_VERSION
            or payload["service"] != POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE
            or payload["status"] != POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STATUS
            or payload["phase"]
            != (
                TrustedTimePostEnrollmentGracefulStopProgressPhase.OPERATION_BOUND_SUPERVISOR_BRIDGE_REQUIRED
            )
            or type(payload["progress_ordinal"]) is not int
            or payload["progress_ordinal"] != 1
        ):
            raise ValueError
        record = TrustedTimePostEnrollmentGracefulStopProgressRecord(
            graceful_stop_operation_id=cast(str, payload["graceful_stop_operation_id"]),
            graceful_stop_target_sha256=cast(str, payload["graceful_stop_target_sha256"]),
            graceful_stop_decision_v1_sha256=cast(str, payload["graceful_stop_decision_v1_sha256"]),
            operator_attestation_envelope_sha256=cast(
                str, payload["operator_attestation_envelope_sha256"]
            ),
            attempt_slot_sha256=cast(str, payload["attempt_slot_sha256"]),
            predecessor_record_sha256=cast(str, payload["predecessor_record_sha256"]),
            _construction_capability=_CONSTRUCTION_CAPABILITY,
        )
        if (
            record.payload() != payload
            or canonical_post_enrollment_graceful_stop_progress_bytes(record) != encoded
        ):
            raise ValueError
        return record
    except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress record is invalid"
        ) from None


def decode_post_enrollment_graceful_stop_outcome_bytes(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopOutcomeRecord:
    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES,
        )
        if set(payload) != _OUTCOME_FIELDS:
            raise ValueError
        if any(payload[field_name] is not False for field_name in _LIFECYCLE_FALSE_FIELDS):
            raise ValueError
        if (
            payload["attempt_slot_reserved"] is not True
            or payload["qualified"] is not False
            or payload["recovery_required"] is not True
            or payload["retry_authorized"] is not False
            or payload["terminal_outcome_retained"] is not True
            or payload["contract_version"]
            != POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_CONTRACT_VERSION
            or payload["service"] != POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE
            or payload["status"] != POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS
            or payload["reason"] != POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON
            or payload["latest_progress_phase"]
            != (
                TrustedTimePostEnrollmentGracefulStopProgressPhase.OPERATION_BOUND_SUPERVISOR_BRIDGE_REQUIRED
            )
            or type(payload["progress_ordinal"]) is not int
            or payload["progress_ordinal"] != 1
        ):
            raise ValueError
        record = TrustedTimePostEnrollmentGracefulStopOutcomeRecord(
            graceful_stop_operation_id=cast(str, payload["graceful_stop_operation_id"]),
            graceful_stop_target_sha256=cast(str, payload["graceful_stop_target_sha256"]),
            graceful_stop_decision_v1_sha256=cast(str, payload["graceful_stop_decision_v1_sha256"]),
            operator_attestation_envelope_sha256=cast(
                str, payload["operator_attestation_envelope_sha256"]
            ),
            attempt_slot_sha256=cast(str, payload["attempt_slot_sha256"]),
            latest_progress_record_sha256=cast(str, payload["latest_progress_record_sha256"]),
            progress_transcript_sha256=cast(str, payload["progress_transcript_sha256"]),
            _construction_capability=_CONSTRUCTION_CAPABILITY,
        )
        if (
            record.payload() != payload
            or canonical_post_enrollment_graceful_stop_outcome_bytes(record) != encoded
        ):
            raise ValueError
        return record
    except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome record is invalid"
        ) from None


def _new_attempt_record(
    *,
    decision: TrustedTimePostEnrollmentGracefulStopDecision,
    envelope: TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    verification: TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
) -> TrustedTimePostEnrollmentGracefulStopAttemptRecord:
    if (
        type(decision) is not TrustedTimePostEnrollmentGracefulStopDecision
        or type(envelope) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope
        or type(verification)
        is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt binding is invalid"
        )
    decision_encoded = canonical_post_enrollment_graceful_stop_decision_bytes(decision)
    envelope_encoded = canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(
        envelope
    )
    verification.__post_init__()
    decision_payload = _decode_canonical_object(
        decision_encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES,
    )
    envelope_payload = _decode_canonical_object(
        envelope_encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    )
    embedded_decision_encoded = _decode_canonical_base64(
        envelope_payload["graceful_stop_decision_v1_base64"]
    )
    if embedded_decision_encoded != decision_encoded:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt binding is invalid"
        )
    target_encoded = _nested_encoded(decision_payload["graceful_stop_target"])
    target = cast(dict[str, object], decision_payload["graceful_stop_target"])
    locator_encoded = _nested_encoded(target["durable_shutdown_locator"])
    statement = cast(dict[str, object], envelope_payload["operator_attestation_statement"])
    statement_encoded = _nested_encoded(statement)
    signature = _decode_canonical_base64(envelope_payload["signature_base64"], exact_length=64)
    decision_sha256 = hashlib.sha256(decision_encoded).hexdigest()
    target_sha256 = hashlib.sha256(target_encoded).hexdigest()
    envelope_sha256 = hashlib.sha256(envelope_encoded).hexdigest()
    statement_sha256 = hashlib.sha256(statement_encoded).hexdigest()
    signature_sha256 = hashlib.sha256(signature).hexdigest()
    if (
        verification.graceful_stop_operation_id != decision_payload["operation_id"]
        or verification.graceful_stop_target_sha256 != target_sha256
        or verification.graceful_stop_decision_v1_sha256 != decision_sha256
        or verification.operator_attestation_envelope_sha256 != envelope_sha256
        or verification.operator_attestation_statement_sha256 != statement_sha256
        or verification.operator_attestation_signature_sha256 != signature_sha256
        or verification.authority_artifact_sha256 != statement["authority_artifact_sha256"]
        or verification.public_key_sha256 != statement["public_key_sha256"]
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt binding is invalid"
        )
    return TrustedTimePostEnrollmentGracefulStopAttemptRecord(
        graceful_stop_operation_id=cast(str, decision_payload["operation_id"]),
        graceful_stop_target_sha256=target_sha256,
        graceful_stop_decision_v1_sha256=decision_sha256,
        operator_attestation_envelope_sha256=envelope_sha256,
        operator_attestation_statement_sha256=statement_sha256,
        operator_attestation_signature_sha256=signature_sha256,
        operator_authority_artifact_sha256=verification.authority_artifact_sha256,
        operator_public_key_sha256=verification.public_key_sha256,
        controller_outcome_sha256=cast(str, target["controller_outcome_sha256"]),
        durable_shutdown_locator_sha256=cast(str, target["durable_shutdown_locator_sha256"]),
        start_operation_id=cast(str, target["start_operation_id"]),
        start_approval_sha256=cast(str, target["start_approval_sha256"]),
        start_execution_attempt_slot_sha256=cast(
            str, target["start_execution_attempt_slot_sha256"]
        ),
        start_operator_attestation_envelope_sha256=(
            cast(str, target["start_operator_attestation_envelope_sha256"])
        ),
        envelope_encoded=envelope_encoded,
        locator_encoded=locator_encoded,
        _construction_capability=_CONSTRUCTION_CAPABILITY,
    )


def _new_progress_record(
    attempt: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
) -> TrustedTimePostEnrollmentGracefulStopProgressRecord:
    if type(attempt) is not TrustedTimePostEnrollmentGracefulStopAttemptRecord:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress binding is invalid"
        )
    attempt_encoded = attempt.encoded
    attempt_sha256 = hashlib.sha256(attempt_encoded).hexdigest()
    return TrustedTimePostEnrollmentGracefulStopProgressRecord(
        graceful_stop_operation_id=attempt.graceful_stop_operation_id,
        graceful_stop_target_sha256=attempt.graceful_stop_target_sha256,
        graceful_stop_decision_v1_sha256=attempt.graceful_stop_decision_v1_sha256,
        operator_attestation_envelope_sha256=attempt.operator_attestation_envelope_sha256,
        attempt_slot_sha256=attempt_sha256,
        predecessor_record_sha256=attempt_sha256,
        _construction_capability=_CONSTRUCTION_CAPABILITY,
    )


def _new_outcome_record(
    attempt: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
    progress: TrustedTimePostEnrollmentGracefulStopProgressRecord,
) -> TrustedTimePostEnrollmentGracefulStopOutcomeRecord:
    if (
        type(attempt) is not TrustedTimePostEnrollmentGracefulStopAttemptRecord
        or type(progress) is not TrustedTimePostEnrollmentGracefulStopProgressRecord
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome binding is invalid"
        )
    attempt_encoded = attempt.encoded
    attempt_sha256 = hashlib.sha256(attempt_encoded).hexdigest()
    progress.__post_init__()
    if (
        progress.graceful_stop_operation_id != attempt.graceful_stop_operation_id
        or progress.graceful_stop_target_sha256 != attempt.graceful_stop_target_sha256
        or progress.graceful_stop_decision_v1_sha256 != attempt.graceful_stop_decision_v1_sha256
        or progress.operator_attestation_envelope_sha256
        != attempt.operator_attestation_envelope_sha256
        or progress.attempt_slot_sha256 != attempt_sha256
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome binding is invalid"
        )
    return TrustedTimePostEnrollmentGracefulStopOutcomeRecord(
        graceful_stop_operation_id=attempt.graceful_stop_operation_id,
        graceful_stop_target_sha256=attempt.graceful_stop_target_sha256,
        graceful_stop_decision_v1_sha256=attempt.graceful_stop_decision_v1_sha256,
        operator_attestation_envelope_sha256=attempt.operator_attestation_envelope_sha256,
        attempt_slot_sha256=attempt_sha256,
        latest_progress_record_sha256=progress.record_sha256,
        progress_transcript_sha256=_progress_transcript_sha256(
            attempt_sha256,
            progress.record_sha256,
        ),
        _construction_capability=_CONSTRUCTION_CAPABILITY,
    )


# The repository below is intentionally private.  It is a dormant seam for a later
# operation-bound supervisor bridge; no production module constructs it.

try:
    _FILE_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    _FILE_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    _DIRECTORY_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
except AttributeError:
    # Public operations call `_require_secure_open_flags` before every open, so
    # these inert fallbacks are never consumed on an unsupported platform.
    _FILE_READ_FLAGS = os.O_RDONLY
    _FILE_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL
    _DIRECTORY_READ_FLAGS = os.O_RDONLY
_RECEIPT_CONSTRUCTION_CAPABILITY = object()
_REPOSITORY_CONSTRUCTION_CAPABILITY = object()
_MAXIMUM_COMMIT_BYTES = 4 * 1_024
_MAXIMUM_SHARED_DIRECTORY_ENTRIES = 4_096
_COMMIT_FIELDS = frozenset(
    {
        "attempt_slot_sha256",
        "contract_version",
        "latest_progress_record_sha256",
        "outcome_sha256",
        "service",
        "status",
    }
)


class _ExclusiveCreateAlreadyExists(Exception):
    pass


def _require_secure_open_flags() -> None:
    try:
        required_flags = (
            os.O_CLOEXEC,
            os.O_DIRECTORY,
            os.O_NOFOLLOW,
            os.O_NONBLOCK,
        )
    except AttributeError:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop secure file flags are unavailable"
        ) from None
    if any(type(flag) is not int or flag == 0 for flag in required_flags):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop secure file flags are unavailable"
        )


def _run_cleanup_operations(
    active_error: BaseException | None,
    operations: tuple[Callable[[], None], ...],
) -> None:
    first_cleanup_error: BaseException | None = None
    for operation in operations:
        try:
            operation()
        except BaseException as error:
            if first_cleanup_error is None:
                first_cleanup_error = error
    if active_error is None and first_cleanup_error is not None:
        raise first_cleanup_error


class _OwnedFileDescriptor(ctypes.c_int):
    """Own one libc-opened descriptor before the Python CALL can return."""

    def __index__(self) -> int:
        return self.fileno()

    def fileno(self) -> int:
        descriptor = self.value
        if descriptor < 0:
            raise OSError
        return descriptor

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        self.value = -1
        os.close(descriptor)

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


_LIBC = ctypes.CDLL(None, use_errno=True)
_OWNED_OPEN = _LIBC.open
_OWNED_OPEN.argtypes = (ctypes.c_char_p, ctypes.c_int)
_OWNED_OPEN.restype = _OwnedFileDescriptor
_OWNED_OPENAT = _LIBC.openat
_OWNED_OPENAT.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
_OWNED_OPENAT.restype = _OwnedFileDescriptor


def _open_owned_descriptor(
    path: str | Path,
    *,
    flags: int,
    mode: int = 0,
    directory_descriptor: int | None = None,
) -> _OwnedFileDescriptor:
    _require_secure_open_flags()
    ctypes.set_errno(0)
    if directory_descriptor is None:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPEN(os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    else:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPENAT(
                directory_descriptor,
                os.fsencode(path),
                flags,
                ctypes.c_int(mode),
            ),
        )
    if owner.value >= 0:
        return owner
    error_number = ctypes.get_errno() or errno.EIO
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), os.fspath(path))
    if error_number == errno.ENOENT:
        raise FileNotFoundError(error_number, os.strerror(error_number), os.fspath(path))
    raise OSError(error_number, os.strerror(error_number), os.fspath(path))


def _validate_file_identity(
    identity: object,
    *,
    encoded_size: int,
) -> tuple[int, ...]:
    if (
        type(identity) is not tuple
        or len(identity) != 9
        or any(type(value) is not int for value in identity)
    ):
        raise ValueError
    exact = cast(tuple[int, ...], identity)
    if (
        not stat.S_ISREG(exact[2])
        or stat.S_IMODE(exact[2]) != 0o600
        or exact[3] != os.geteuid()
        or exact[5] != 1
        or exact[6] != encoded_size
    ):
        raise ValueError
    return exact


@dataclass(frozen=True, slots=True, init=False, eq=False)
class RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
    """Exact durable ordinal-zero record and inode observation."""

    record: TrustedTimePostEnrollmentGracefulStopAttemptRecord
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        record: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
        artifact_sha256: str,
        artifact_path: Path,
        encoded: bytes,
        file_identity: tuple[int, ...],
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained attempt must be loaded or issued"
            )
        values = (record, artifact_sha256, artifact_path, encoded, file_identity)
        for name, value in zip(
            ("record", "artifact_sha256", "artifact_path", "encoded", "file_identity"),
            values,
            strict=True,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                or type(self.record) is not TrustedTimePostEnrollmentGracefulStopAttemptRecord
                or type(self.artifact_path) is not type(Path())
                or type(self.encoded) is not bytes
                or type(self.file_identity) is not tuple
                or type(self._sealed_fields) is not tuple
            ):
                raise ValueError
            record_encoded = self.record.encoded
            if (
                not _is_sha256(self.artifact_sha256)
                or not self.artifact_path.is_absolute()
                or self.artifact_path != Path(os.path.abspath(self.artifact_path))
                or self.artifact_path.name != POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
                or not self.encoded
                or len(self.encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES
                or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
                or hashlib.sha256(record_encoded).hexdigest() != self.artifact_sha256
                or record_encoded != self.encoded
                or _validate_file_identity(
                    self.file_identity,
                    encoded_size=len(self.encoded),
                )
                != self.file_identity
                or self._sealed_fields
                != (
                    self.record,
                    self.artifact_sha256,
                    self.artifact_path,
                    self.encoded,
                    self.file_identity,
                )
            ):
                raise ValueError
        except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained attempt is invalid"
            ) from None

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


@dataclass(frozen=True, slots=True, init=False, eq=False)
class RetainedTrustedTimePostEnrollmentGracefulStopProgress:
    """Exact immutable ordinal-one record and predecessor observation."""

    record: TrustedTimePostEnrollmentGracefulStopProgressRecord
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]
    attempt_slot_file_identity: tuple[int, ...]
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        record: TrustedTimePostEnrollmentGracefulStopProgressRecord,
        artifact_sha256: str,
        artifact_path: Path,
        encoded: bytes,
        file_identity: tuple[int, ...],
        attempt_slot_file_identity: tuple[int, ...],
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained progress must be loaded or issued"
            )
        values = (
            record,
            artifact_sha256,
            artifact_path,
            encoded,
            file_identity,
            attempt_slot_file_identity,
        )
        for name, value in zip(
            (
                "record",
                "artifact_sha256",
                "artifact_path",
                "encoded",
                "file_identity",
                "attempt_slot_file_identity",
            ),
            values,
            strict=True,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                or type(self.record) is not TrustedTimePostEnrollmentGracefulStopProgressRecord
                or type(self.artifact_path) is not type(Path())
                or type(self.encoded) is not bytes
                or type(self.file_identity) is not tuple
                or type(self.attempt_slot_file_identity) is not tuple
                or len(self.attempt_slot_file_identity) != 9
                or any(type(value) is not int for value in self.attempt_slot_file_identity)
                or type(self._sealed_fields) is not tuple
            ):
                raise ValueError
            expected_name = _progress_file_name(self.artifact_sha256)
            if (
                not _is_sha256(self.artifact_sha256)
                or not self.artifact_path.is_absolute()
                or self.artifact_path != Path(os.path.abspath(self.artifact_path))
                or self.artifact_path.name != expected_name
                or not self.encoded
                or len(self.encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES
                or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
                or self.record.record_sha256 != self.artifact_sha256
                or self.record.encoded != self.encoded
                or _validate_file_identity(
                    self.file_identity,
                    encoded_size=len(self.encoded),
                )
                != self.file_identity
                or _validate_file_identity(
                    self.attempt_slot_file_identity,
                    encoded_size=self.attempt_slot_file_identity[6],
                )
                != self.attempt_slot_file_identity
                or self._sealed_fields
                != (
                    self.record,
                    self.artifact_sha256,
                    self.artifact_path,
                    self.encoded,
                    self.file_identity,
                    self.attempt_slot_file_identity,
                )
            ):
                raise ValueError
        except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained progress is invalid"
            ) from None

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


@dataclass(frozen=True, slots=True, init=False, eq=False)
class RetainedTrustedTimePostEnrollmentGracefulStopOutcome:
    """Exact committed recovery-only outcome and full chain observation."""

    record: TrustedTimePostEnrollmentGracefulStopOutcomeRecord
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]
    attempt_slot_file_identity: tuple[int, ...]
    progress_file_identity: tuple[int, ...]
    commit_encoded: bytes
    commit_file_identity: tuple[int, ...]
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        record: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
        artifact_sha256: str,
        artifact_path: Path,
        encoded: bytes,
        file_identity: tuple[int, ...],
        attempt_slot_file_identity: tuple[int, ...],
        progress_file_identity: tuple[int, ...],
        commit_encoded: bytes,
        commit_file_identity: tuple[int, ...],
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained outcome must be loaded or issued"
            )
        values = (
            record,
            artifact_sha256,
            artifact_path,
            encoded,
            file_identity,
            attempt_slot_file_identity,
            progress_file_identity,
            commit_encoded,
            commit_file_identity,
        )
        for name, value in zip(
            (
                "record",
                "artifact_sha256",
                "artifact_path",
                "encoded",
                "file_identity",
                "attempt_slot_file_identity",
                "progress_file_identity",
                "commit_encoded",
                "commit_file_identity",
            ),
            values,
            strict=True,
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                or type(self.record) is not TrustedTimePostEnrollmentGracefulStopOutcomeRecord
                or type(self.artifact_path) is not type(Path())
                or type(self.encoded) is not bytes
                or type(self.commit_encoded) is not bytes
                or type(self.file_identity) is not tuple
                or type(self.attempt_slot_file_identity) is not tuple
                or len(self.attempt_slot_file_identity) != 9
                or any(type(value) is not int for value in self.attempt_slot_file_identity)
                or type(self.progress_file_identity) is not tuple
                or len(self.progress_file_identity) != 9
                or any(type(value) is not int for value in self.progress_file_identity)
                or type(self.commit_file_identity) is not tuple
                or type(self._sealed_fields) is not tuple
            ):
                raise ValueError
            expected_name = _outcome_file_name(self.artifact_sha256)
            expected_commit = _outcome_commit_bytes(self.record)
            if (
                not _is_sha256(self.artifact_sha256)
                or not self.artifact_path.is_absolute()
                or self.artifact_path != Path(os.path.abspath(self.artifact_path))
                or self.artifact_path.name != expected_name
                or not self.encoded
                or len(self.encoded) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES
                or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
                or self.record.record_sha256 != self.artifact_sha256
                or self.record.encoded != self.encoded
                or self.commit_encoded != expected_commit
                or _validate_file_identity(
                    self.file_identity,
                    encoded_size=len(self.encoded),
                )
                != self.file_identity
                or _validate_file_identity(
                    self.attempt_slot_file_identity,
                    encoded_size=self.attempt_slot_file_identity[6],
                )
                != self.attempt_slot_file_identity
                or _validate_file_identity(
                    self.progress_file_identity,
                    encoded_size=self.progress_file_identity[6],
                )
                != self.progress_file_identity
                or _validate_file_identity(
                    self.commit_file_identity,
                    encoded_size=len(self.commit_encoded),
                )
                != self.commit_file_identity
                or self._sealed_fields
                != (
                    self.record,
                    self.artifact_sha256,
                    self.artifact_path,
                    self.encoded,
                    self.file_identity,
                    self.attempt_slot_file_identity,
                    self.progress_file_identity,
                    self.commit_encoded,
                    self.commit_file_identity,
                )
            ):
                raise ValueError
        except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop retained outcome is invalid"
            ) from None

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimePostEnrollmentGracefulStopRecoveryState:
    """Non-authorizing classification of the one durable lifecycle chain."""

    status: TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus
    attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None
    progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None
    outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        status: TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus,
        attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None,
        progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None,
        outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _RECEIPT_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop recovery state must be inspected"
            )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "progress", progress)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "_sealed_fields", (status, attempt, progress, outcome))
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not TrustedTimePostEnrollmentGracefulStopRecoveryState
                or type(self._sealed_fields) is not tuple
            ):
                raise ValueError
            exact_fields = (self.status, self.attempt, self.progress, self.outcome)
            valid = (
                (
                    self.status
                    is TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.UNRESERVED
                    and self.attempt is None
                    and self.progress is None
                    and self.outcome is None
                )
                or (
                    self.status
                    is (
                        TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
                    )
                    and self.attempt is None
                    and self.progress is None
                    and self.outcome is None
                )
                or (
                    self.status
                    is TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
                    and type(self.attempt) is RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                    and (
                        self.progress is None
                        or type(self.progress)
                        is RetainedTrustedTimePostEnrollmentGracefulStopProgress
                    )
                    and self.outcome is None
                )
                or (
                    self.status
                    is (
                        TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.TERMINAL_OUTCOME_RETAINED
                    )
                    and type(self.attempt) is RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                    and type(self.progress) is RetainedTrustedTimePostEnrollmentGracefulStopProgress
                    and type(self.outcome) is RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                )
            )
            if not valid or self._sealed_fields != exact_fields:
                raise ValueError
            if self.attempt is not None:
                self.attempt.__post_init__()
            if self.progress is not None:
                self.progress.__post_init__()
                if (
                    self.attempt is None
                    or self.progress.record.attempt_slot_sha256 != self.attempt.artifact_sha256
                    or self.progress.attempt_slot_file_identity != self.attempt.file_identity
                    or self.progress.artifact_path.parent != self.attempt.artifact_path.parent
                ):
                    raise ValueError
                _validate_progress_binding(self.attempt.record, self.progress.record)
            if self.outcome is not None:
                self.outcome.__post_init__()
                if (
                    self.attempt is None
                    or self.progress is None
                    or self.outcome.attempt_slot_file_identity != self.attempt.file_identity
                    or self.outcome.progress_file_identity != self.progress.file_identity
                    or self.outcome.artifact_path.parent != self.attempt.artifact_path.parent
                ):
                    raise ValueError
                _validate_outcome_binding(
                    self.attempt.record,
                    self.progress.record,
                    self.outcome.record,
                )
        except TrustedTimePostEnrollmentGracefulStopLifecycleRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop recovery state is invalid"
            ) from None

    @property
    def recovery_required(self) -> bool:
        self.__post_init__()
        return (
            self.status is not TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.UNRESERVED
        )

    @property
    def retry_authorized(self) -> bool:
        self.__post_init__()
        return False

    @property
    def continuation_authorized(self) -> bool:
        self.__post_init__()
        return False

    @property
    def terminal_outcome_retained(self) -> bool:
        self.__post_init__()
        return (
            self.status
            is TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.TERMINAL_OUTCOME_RETAINED
        )

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _artifact_directory(artifact_directory: Path, *, ignored_root: Path) -> Path:
    if (
        type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or not artifact_directory.is_absolute()
        or not ignored_root.is_absolute()
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop lifecycle directory is invalid"
        )
    try:
        root = Path(os.path.abspath(ignored_root))
        directory = Path(os.path.abspath(artifact_directory))
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop lifecycle directory is invalid"
        ) from None
    if (
        artifact_directory != directory
        or ignored_root != root
        or directory != root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop lifecycle directory is invalid"
        )
    return directory


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
    create: bool,
) -> _OwnedFileDescriptor:
    _require_secure_open_flags()
    absolute = _artifact_directory(path, ignored_root=ignored_root)
    root = ignored_root
    owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    active_error: BaseException | None = None
    completed = False
    current = Path(absolute.anchor)
    try:
        owner = _open_owned_descriptor(absolute.anchor, flags=_DIRECTORY_READ_FLAGS)
        for part in absolute.parts[1:]:
            current /= part
            protected = current == root or current.is_relative_to(root)
            created = False
            if protected and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=owner.fileno())
                    created = True
                except FileExistsError:
                    pass
            next_owner = _open_owned_descriptor(
                part,
                flags=_DIRECTORY_READ_FLAGS,
                directory_descriptor=owner.fileno(),
            )
            metadata = os.fstat(next_owner.fileno())
            if created:
                os.fchmod(next_owner.fileno(), 0o700)
                os.fsync(next_owner.fileno())
                os.fsync(owner.fileno())
                metadata = os.fstat(next_owner.fileno())
            if protected and (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise OSError
            previous_owner = owner
            owner = next_owner
            next_owner = None
            previous_owner.close()
        completed = True
        return owner
    except OSError:
        active_error = TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop lifecycle directory is unavailable"
        )
        raise active_error from None
    except BaseException as error:
        active_error = error
        raise
    finally:
        if not completed:
            cleanup_operations = tuple(
                candidate.close for candidate in (next_owner, owner) if candidate is not None
            )
            _run_cleanup_operations(active_error, cleanup_operations)


def _is_lifecycle_name(name: str) -> bool:
    return name.startswith(".post-enrollment-graceful-stop-") or name.startswith(
        "trusted-time-post-enrollment-graceful-stop-"
    )


def _lifecycle_names(directory_descriptor: int) -> frozenset[str]:
    try:
        before = os.fstat(directory_descriptor)
        names: list[str] = []
        total_entries = 0
        iterator: Any | None = None
        iterator_error: BaseException | None = None
        try:
            iterator = os.scandir(directory_descriptor)
            for entry in iterator:
                name = entry.name
                total_entries += 1
                if (
                    type(name) is not str
                    or not name
                    or len(os.fsencode(name))
                    > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_FILE_NAME_BYTES
                    or total_entries > _MAXIMUM_SHARED_DIRECTORY_ENTRIES
                ):
                    raise OSError
                if _is_lifecycle_name(name):
                    if len(names) == MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_ENTRIES:
                        raise OSError
                    names.append(name)
        except BaseException as error:
            iterator_error = error
            raise
        finally:
            if iterator is not None:
                retained_iterator = iterator
                iterator = None
                _run_cleanup_operations(iterator_error, (retained_iterator.close,))
        after = os.fstat(directory_descriptor)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise OSError
        return frozenset(name for name in names if _is_lifecycle_name(name))
    except OSError:
        raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop lifecycle inventory is unavailable"
        ) from None


def _validate_file_name(file_name: str) -> str:
    if (
        type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_FILE_NAME_BYTES
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop lifecycle file name is invalid"
        )
    return file_name


def _progress_file_name(record_sha256: str) -> str:
    if not _is_sha256(record_sha256):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress file binding is invalid"
        )
    return _validate_file_name(
        f"{POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX}"
        f"{record_sha256}{POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_SUFFIX}"
    )


def _outcome_file_name(record_sha256: str) -> str:
    if not _is_sha256(record_sha256):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome file binding is invalid"
        )
    return _validate_file_name(
        f"{POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_PREFIX}"
        f"{record_sha256}{POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_SUFFIX}"
    )


def _write_all(descriptor: int, encoded: bytes) -> None:
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError
        view = view[written:]


def _read_descriptor(
    directory_descriptor: int,
    descriptor: int,
    *,
    file_name: str,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    try:
        directory_before = os.fstat(directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise OSError
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = bytearray()
        while len(retained) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(retained)))
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        directory_after = os.fstat(directory_descriptor)
        if (
            _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(named)
            or _stable_file_identity(directory_before) != _stable_file_identity(directory_after)
            or len(retained) != before.st_size
            or len(retained) > maximum_bytes
        ):
            raise OSError
        return bytes(retained), _stable_file_identity(before)
    except OSError:
        raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop lifecycle evidence is unavailable"
        ) from None


def _read_named_file(
    directory_descriptor: int,
    *,
    file_name: str,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    _require_secure_open_flags()
    owner: _OwnedFileDescriptor | None = None
    active_error: BaseException | None = None
    try:
        owner = _open_owned_descriptor(
            _validate_file_name(file_name),
            flags=_FILE_READ_FLAGS,
            directory_descriptor=directory_descriptor,
        )
        retained = _read_descriptor(
            directory_descriptor,
            owner.fileno(),
            file_name=file_name,
            maximum_bytes=maximum_bytes,
        )
        owner.close()
        return retained
    except OSError:
        active_error = TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop lifecycle evidence is unavailable"
        )
        raise active_error from None
    except BaseException as error:
        active_error = error
        raise
    finally:
        if owner is not None:
            _run_cleanup_operations(
                active_error,
                (owner.close,),
            )


@contextmanager
def _locked_attempt_slot(
    directory_descriptor: int,
    *,
    exclusive: bool,
) -> Iterator[tuple[int, frozenset[str]]]:
    _require_secure_open_flags()
    owner: _OwnedFileDescriptor | None = None
    directory_locked = False
    active_error: BaseException | None = None
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        directory_locked = True
        owner = _open_owned_descriptor(
            POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
            flags=_FILE_READ_FLAGS,
            directory_descriptor=directory_descriptor,
        )
        descriptor = owner.fileno()
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise OSError
        fcntl.flock(
            descriptor,
            (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB,
        )
        names = _lifecycle_names(directory_descriptor)
        fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        directory_locked = False
        yield descriptor, names
    except OSError:
        active_error = TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop attempt slot is unavailable"
        )
        raise active_error from None
    except BaseException as error:
        active_error = error
        raise
    finally:
        cleanup_operations: list[Callable[[], None]] = []
        if directory_locked:
            directory_locked = False
            cleanup_operations.append(lambda: fcntl.flock(directory_descriptor, fcntl.LOCK_UN))
        if owner is not None:
            cleanup_operations.extend(
                (
                    lambda: fcntl.flock(owner.fileno(), fcntl.LOCK_UN),
                    owner.close,
                )
            )
        _run_cleanup_operations(active_error, tuple(cleanup_operations))


def _create_fsynced_file(
    directory_descriptor: int,
    *,
    file_name: str,
    encoded: bytes,
) -> tuple[_OwnedFileDescriptor, tuple[int, ...]]:
    try:
        owner = _open_owned_descriptor(
            _validate_file_name(file_name),
            flags=_FILE_CREATE_FLAGS,
            mode=0o600,
            directory_descriptor=directory_descriptor,
        )
    except FileExistsError:
        raise _ExclusiveCreateAlreadyExists from None
    descriptor = owner.fileno()
    try:
        _write_all(descriptor, encoded)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(encoded)
        ):
            raise OSError
        return owner, _stable_file_identity(metadata)
    except BaseException:
        with suppress(BaseException):
            owner.close()
        raise


def _publish_staged_file(
    directory_descriptor: int,
    *,
    staging_file_name: str,
    final_file_name: str,
    encoded: bytes,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    owner: _OwnedFileDescriptor | None = None
    active_error: BaseException | None = None
    try:
        owner, _ = _create_fsynced_file(
            directory_descriptor,
            file_name=staging_file_name,
            encoded=encoded,
        )
        descriptor = owner.fileno()
        os.link(
            staging_file_name,
            final_file_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        linked = os.stat(final_file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            _stable_file_identity(linked) != _stable_file_identity(os.fstat(descriptor))
            or linked.st_nlink != 2
        ):
            raise OSError
        os.fsync(directory_descriptor)
        os.unlink(staging_file_name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        retained, identity = _read_descriptor(
            directory_descriptor,
            descriptor,
            file_name=final_file_name,
            maximum_bytes=maximum_bytes,
        )
        if retained != encoded:
            raise OSError
        return retained, identity
    except BaseException as error:
        active_error = error
        raise
    finally:
        if owner is not None:
            if active_error is None:
                owner.close()
            else:
                with suppress(BaseException):
                    owner.close()


def _outcome_commit_payload(
    record: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
) -> dict[str, object]:
    record.__post_init__()
    return {
        "attempt_slot_sha256": record.attempt_slot_sha256,
        "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_CONTRACT_VERSION,
        "latest_progress_record_sha256": record.latest_progress_record_sha256,
        "outcome_sha256": record.record_sha256,
        "service": POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE,
        "status": "committed",
    }


def _outcome_commit_bytes(
    record: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
) -> bytes:
    encoded = canonical_first_enrollment_json_bytes(_outcome_commit_payload(record))
    if len(encoded) > _MAXIMUM_COMMIT_BYTES:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome commit is invalid"
        )
    return encoded


def _decode_outcome_commit_bytes(
    encoded: object,
    *,
    outcome: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
) -> bytes:
    try:
        payload = _decode_canonical_object(encoded, maximum_bytes=_MAXIMUM_COMMIT_BYTES)
        if (
            set(payload) != _COMMIT_FIELDS
            or payload != _outcome_commit_payload(outcome)
            or _outcome_commit_bytes(outcome) != encoded
        ):
            raise ValueError
        return encoded
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome commit is invalid"
        ) from None


def _rebind_exact_files(
    directory_descriptor: int,
    *,
    artifact_directory: Path,
    ignored_root: Path,
    expected_names: frozenset[str],
    expected_files: dict[str, tuple[bytes, tuple[int, ...], int]],
) -> None:
    rebound_owner: _OwnedFileDescriptor | None = None
    active_error: BaseException | None = None
    try:
        rebound_owner = _open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=False,
        )
        if (
            _stable_file_identity(os.fstat(rebound_owner.fileno()))
            != _stable_file_identity(os.fstat(directory_descriptor))
            or _lifecycle_names(rebound_owner.fileno()) != expected_names
        ):
            raise OSError
        for file_name, (encoded, identity, maximum_bytes) in expected_files.items():
            rebound_encoded, rebound_identity = _read_named_file(
                rebound_owner.fileno(),
                file_name=file_name,
                maximum_bytes=maximum_bytes,
            )
            if rebound_encoded != encoded or rebound_identity != identity:
                raise OSError
    except Exception:
        active_error = TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop lifecycle path binding is unavailable"
        )
        raise active_error from None
    except BaseException as error:
        active_error = error
        raise
    finally:
        if rebound_owner is not None:
            _run_cleanup_operations(active_error, (rebound_owner.close,))


def _attempt_receipt(
    *,
    record: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
    artifact_directory: Path,
    encoded: bytes,
    file_identity: tuple[int, ...],
) -> RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
    return RetainedTrustedTimePostEnrollmentGracefulStopAttempt(
        record=record,
        artifact_sha256=hashlib.sha256(encoded).hexdigest(),
        artifact_path=(artifact_directory / POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME),
        encoded=encoded,
        file_identity=file_identity,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _progress_receipt(
    *,
    record: TrustedTimePostEnrollmentGracefulStopProgressRecord,
    artifact_directory: Path,
    encoded: bytes,
    file_identity: tuple[int, ...],
    attempt_slot_file_identity: tuple[int, ...],
) -> RetainedTrustedTimePostEnrollmentGracefulStopProgress:
    return RetainedTrustedTimePostEnrollmentGracefulStopProgress(
        record=record,
        artifact_sha256=record.record_sha256,
        artifact_path=artifact_directory / _progress_file_name(record.record_sha256),
        encoded=encoded,
        file_identity=file_identity,
        attempt_slot_file_identity=attempt_slot_file_identity,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _outcome_receipt(
    *,
    record: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
    artifact_directory: Path,
    encoded: bytes,
    file_identity: tuple[int, ...],
    attempt_slot_file_identity: tuple[int, ...],
    progress_file_identity: tuple[int, ...],
    commit_encoded: bytes,
    commit_file_identity: tuple[int, ...],
) -> RetainedTrustedTimePostEnrollmentGracefulStopOutcome:
    return RetainedTrustedTimePostEnrollmentGracefulStopOutcome(
        record=record,
        artifact_sha256=record.record_sha256,
        artifact_path=artifact_directory / _outcome_file_name(record.record_sha256),
        encoded=encoded,
        file_identity=file_identity,
        attempt_slot_file_identity=attempt_slot_file_identity,
        progress_file_identity=progress_file_identity,
        commit_encoded=commit_encoded,
        commit_file_identity=commit_file_identity,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _validate_progress_binding(
    attempt: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
    progress: TrustedTimePostEnrollmentGracefulStopProgressRecord,
) -> None:
    attempt_sha256 = hashlib.sha256(attempt.encoded).hexdigest()
    if (
        progress.graceful_stop_operation_id != attempt.graceful_stop_operation_id
        or progress.graceful_stop_target_sha256 != attempt.graceful_stop_target_sha256
        or progress.graceful_stop_decision_v1_sha256 != attempt.graceful_stop_decision_v1_sha256
        or progress.operator_attestation_envelope_sha256
        != attempt.operator_attestation_envelope_sha256
        or progress.attempt_slot_sha256 != attempt_sha256
        or progress.predecessor_record_sha256 != attempt_sha256
    ):
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress chain is invalid"
        )


def _validate_outcome_binding(
    attempt: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
    progress: TrustedTimePostEnrollmentGracefulStopProgressRecord,
    outcome: TrustedTimePostEnrollmentGracefulStopOutcomeRecord,
) -> None:
    expected = _new_outcome_record(attempt, progress)
    if expected.encoded != outcome.encoded:
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome chain is invalid"
        )


def _load_chain_from_directory(
    directory_descriptor: int,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> tuple[
    RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    RetainedTrustedTimePostEnrollmentGracefulStopProgress | None,
    RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None,
]:
    with _locked_attempt_slot(
        directory_descriptor,
        exclusive=False,
    ) as (slot_descriptor, names):
        forbidden = {
            POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME,
            POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME,
            POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME,
        }
        if names & forbidden:
            raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                "trusted-time graceful-stop lifecycle chain is unavailable"
            )
        progress_names = frozenset(
            name
            for name in names
            if name.startswith(POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX)
        )
        outcome_names = frozenset(
            name
            for name in names
            if name.startswith(POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_PREFIX)
        )
        known_names = {
            POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
            *progress_names,
            *outcome_names,
        }
        if POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME in names:
            known_names.add(POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME)
        if (
            len(progress_names) > 1
            or len(outcome_names) > 1
            or names != known_names
            or (outcome_names and not progress_names)
            or (
                bool(outcome_names)
                != (POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME in names)
            )
        ):
            raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                "trusted-time graceful-stop lifecycle chain is unavailable"
            )
        directory_before = _stable_file_identity(os.fstat(directory_descriptor))
        attempt_encoded, attempt_identity = _read_descriptor(
            directory_descriptor,
            slot_descriptor,
            file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
        )
        attempt_record = decode_post_enrollment_graceful_stop_attempt_bytes(attempt_encoded)
        attempt = _attempt_receipt(
            record=attempt_record,
            artifact_directory=artifact_directory,
            encoded=attempt_encoded,
            file_identity=attempt_identity,
        )
        progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None = None
        outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None = None
        if progress_names:
            progress_name = next(iter(progress_names))
            progress_encoded, progress_identity = _read_named_file(
                directory_descriptor,
                file_name=progress_name,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
            )
            progress_record = decode_post_enrollment_graceful_stop_progress_bytes(progress_encoded)
            if progress_name != _progress_file_name(progress_record.record_sha256):
                raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                    "trusted-time graceful-stop progress chain is unavailable"
                )
            _validate_progress_binding(attempt_record, progress_record)
            progress = _progress_receipt(
                record=progress_record,
                artifact_directory=artifact_directory,
                encoded=progress_encoded,
                file_identity=progress_identity,
                attempt_slot_file_identity=attempt_identity,
            )
            if outcome_names:
                outcome_name = next(iter(outcome_names))
                outcome_encoded, outcome_identity = _read_named_file(
                    directory_descriptor,
                    file_name=outcome_name,
                    maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES,
                )
                outcome_record = decode_post_enrollment_graceful_stop_outcome_bytes(outcome_encoded)
                if outcome_name != _outcome_file_name(outcome_record.record_sha256):
                    raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                        "trusted-time graceful-stop outcome chain is unavailable"
                    )
                _validate_outcome_binding(attempt_record, progress_record, outcome_record)
                commit_encoded, commit_identity = _read_named_file(
                    directory_descriptor,
                    file_name=POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME,
                    maximum_bytes=_MAXIMUM_COMMIT_BYTES,
                )
                _decode_outcome_commit_bytes(commit_encoded, outcome=outcome_record)
                outcome = _outcome_receipt(
                    record=outcome_record,
                    artifact_directory=artifact_directory,
                    encoded=outcome_encoded,
                    file_identity=outcome_identity,
                    attempt_slot_file_identity=attempt_identity,
                    progress_file_identity=progress_identity,
                    commit_encoded=commit_encoded,
                    commit_file_identity=commit_identity,
                )
        if (
            _lifecycle_names(directory_descriptor) != names
            or _stable_file_identity(os.fstat(directory_descriptor)) != directory_before
        ):
            raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                "trusted-time graceful-stop lifecycle chain is unavailable"
            )
        rebound_owner: _OwnedFileDescriptor | None = None
        rebound_error: BaseException | None = None
        try:
            rebound_owner = _open_owner_only_artifact_directory(
                artifact_directory,
                ignored_root=ignored_root,
                create=False,
            )
            if (
                _stable_file_identity(os.fstat(rebound_owner.fileno())) != directory_before
                or _lifecycle_names(rebound_owner.fileno()) != names
            ):
                raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                    "trusted-time graceful-stop lifecycle path binding is unavailable"
                )
            rebound_attempt_encoded, rebound_attempt_identity = _read_named_file(
                rebound_owner.fileno(),
                file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
            )
            if (
                rebound_attempt_encoded != attempt.encoded
                or rebound_attempt_identity != attempt.file_identity
            ):
                raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                    "trusted-time graceful-stop lifecycle path binding is unavailable"
                )
            if progress is not None:
                rebound_progress_encoded, rebound_progress_identity = _read_named_file(
                    rebound_owner.fileno(),
                    file_name=progress.artifact_path.name,
                    maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
                )
                if (
                    rebound_progress_encoded != progress.encoded
                    or rebound_progress_identity != progress.file_identity
                ):
                    raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                        "trusted-time graceful-stop lifecycle path binding is unavailable"
                    )
            if outcome is not None:
                rebound_outcome_encoded, rebound_outcome_identity = _read_named_file(
                    rebound_owner.fileno(),
                    file_name=outcome.artifact_path.name,
                    maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES,
                )
                rebound_commit_encoded, rebound_commit_identity = _read_named_file(
                    rebound_owner.fileno(),
                    file_name=POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME,
                    maximum_bytes=_MAXIMUM_COMMIT_BYTES,
                )
                if (
                    rebound_outcome_encoded != outcome.encoded
                    or rebound_outcome_identity != outcome.file_identity
                    or rebound_commit_encoded != outcome.commit_encoded
                    or rebound_commit_identity != outcome.commit_file_identity
                ):
                    raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
                        "trusted-time graceful-stop lifecycle path binding is unavailable"
                    )
        except BaseException as error:
            rebound_error = error
            raise
        finally:
            if rebound_owner is not None:
                _run_cleanup_operations(rebound_error, (rebound_owner.close,))
        return attempt, progress, outcome


def _load_chain(
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> tuple[
    RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    RetainedTrustedTimePostEnrollmentGracefulStopProgress | None,
    RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None,
]:
    directory = _artifact_directory(artifact_directory, ignored_root=ignored_root)
    directory_owner: _OwnedFileDescriptor | None = None
    active_error: BaseException | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            directory,
            ignored_root=ignored_root,
            create=False,
        )
        retained = _load_chain_from_directory(
            directory_owner.fileno(),
            artifact_directory=directory,
            ignored_root=ignored_root,
        )
        directory_owner.close()
        return retained
    except TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable as error:
        active_error = error
        raise
    except Exception:
        active_error = TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop lifecycle chain is unavailable"
        )
        raise active_error from None
    except BaseException as error:
        active_error = error
        raise
    finally:
        if directory_owner is not None:
            _run_cleanup_operations(active_error, (directory_owner.close,))


def _same_attempt_receipt(
    left: object,
    right: object,
) -> bool:
    try:
        if (
            type(left) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
            or type(right) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
        ):
            return False
        left.__post_init__()
        right.__post_init__()
        return (
            left.artifact_sha256 == right.artifact_sha256
            and left.artifact_path == right.artifact_path
            and left.encoded == right.encoded
            and left.file_identity == right.file_identity
        )
    except Exception:
        return False


def _same_progress_receipt(
    left: object,
    right: object,
) -> bool:
    try:
        if (
            type(left) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
            or type(right) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
        ):
            return False
        left.__post_init__()
        right.__post_init__()
        return (
            left.artifact_sha256 == right.artifact_sha256
            and left.artifact_path == right.artifact_path
            and left.encoded == right.encoded
            and left.file_identity == right.file_identity
            and left.attempt_slot_file_identity == right.attempt_slot_file_identity
        )
    except Exception:
        return False


def _same_outcome_receipt(
    left: object,
    right: object,
) -> bool:
    try:
        if (
            type(left) is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
            or type(right) is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
        ):
            return False
        left.__post_init__()
        right.__post_init__()
        return (
            left.artifact_sha256 == right.artifact_sha256
            and left.artifact_path == right.artifact_path
            and left.encoded == right.encoded
            and left.file_identity == right.file_identity
            and left.attempt_slot_file_identity == right.attempt_slot_file_identity
            and left.progress_file_identity == right.progress_file_identity
            and left.commit_encoded == right.commit_encoded
            and left.commit_file_identity == right.commit_file_identity
        )
    except Exception:
        return False


def _persist_attempt(
    record: TrustedTimePostEnrollmentGracefulStopAttemptRecord,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
    directory = _artifact_directory(artifact_directory, ignored_root=ignored_root)
    encoded = record.encoded
    record_sha256 = hashlib.sha256(encoded).hexdigest()
    directory_owner: _OwnedFileDescriptor | None = None
    owner: _OwnedFileDescriptor | None = None
    directory_locked = False
    mutation_started = False
    preexisting_evidence_observed = False
    active_error: BaseException | None = None

    def validate_exact_existing_root() -> None:
        if directory_owner is None:
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop attempt retention is unconfirmed"
            )
        directory_descriptor = directory_owner.fileno()
        expected_names = frozenset({POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME})
        if _lifecycle_names(directory_descriptor) != expected_names:
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop attempt retention is unconfirmed"
            )
        observed, observed_identity = _read_named_file(
            directory_descriptor,
            file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
        )
        _, observed_record_sha256 = _decode_post_enrollment_graceful_stop_attempt_material(observed)
        if observed_record_sha256 != hashlib.sha256(observed).hexdigest():
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop attempt retention is unconfirmed"
            )
        _rebind_exact_files(
            directory_descriptor,
            artifact_directory=directory,
            ignored_root=ignored_root,
            expected_names=expected_names,
            expected_files={
                POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME: (
                    observed,
                    observed_identity,
                    MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
                )
            },
        )

    try:
        directory_owner = _open_owner_only_artifact_directory(
            directory,
            ignored_root=ignored_root,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory_locked = True
        if _lifecycle_names(directory_descriptor):
            preexisting_evidence_observed = True
            validate_exact_existing_root()
            raise TrustedTimePostEnrollmentGracefulStopAttemptConsumed(
                "trusted-time graceful-stop attempt slot was already consumed"
            )
        mutation_started = True
        try:
            owner, _ = _create_fsynced_file(
                directory_descriptor,
                file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                encoded=encoded,
            )
        except _ExclusiveCreateAlreadyExists:
            preexisting_evidence_observed = True
            validate_exact_existing_root()
            raise TrustedTimePostEnrollmentGracefulStopAttemptConsumed(
                "trusted-time graceful-stop attempt slot was already consumed"
            ) from None
        slot_descriptor = owner.fileno()
        fcntl.flock(slot_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(directory_descriptor)
        retained, file_identity = _read_descriptor(
            directory_descriptor,
            slot_descriptor,
            file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
        )
        if (
            retained != encoded
            or hashlib.sha256(retained).hexdigest() != record_sha256
            or _lifecycle_names(directory_descriptor)
            != frozenset({POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME})
        ):
            raise OSError
        _rebind_exact_files(
            directory_descriptor,
            artifact_directory=directory,
            ignored_root=ignored_root,
            expected_names=frozenset({POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME}),
            expected_files={
                POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME: (
                    retained,
                    file_identity,
                    MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
                )
            },
        )
        receipt = _attempt_receipt(
            record=record,
            artifact_directory=directory,
            encoded=retained,
            file_identity=file_identity,
        )
        cleanup_operations: list[Callable[[], None]] = []
        directory_locked = False
        cleanup_operations.append(lambda: fcntl.flock(directory_owner.fileno(), fcntl.LOCK_UN))
        cleanup_operations.append(owner.close)
        cleanup_operations.append(directory_owner.close)
        _run_cleanup_operations(None, tuple(cleanup_operations))
        return receipt
    except TrustedTimePostEnrollmentGracefulStopAttemptConsumed:
        consumed = TrustedTimePostEnrollmentGracefulStopAttemptConsumed(
            "trusted-time graceful-stop attempt slot was already consumed"
        )
        active_error = consumed
        raise consumed from None
    except BaseException as error:
        active_error = error
        if mutation_started or preexisting_evidence_observed:
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop attempt retention is unconfirmed"
            ) from None
        if isinstance(error, TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            raise
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop attempt reservation was rejected"
        ) from None
    finally:
        cleanup_operations = []
        if directory_locked and directory_owner is not None:
            directory_locked = False
            cleanup_operations.append(lambda: fcntl.flock(directory_owner.fileno(), fcntl.LOCK_UN))
        if owner is not None:
            cleanup_operations.append(owner.close)
        if directory_owner is not None:
            cleanup_operations.append(directory_owner.close)
        _run_cleanup_operations(active_error, tuple(cleanup_operations))


def _persist_progress(
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopProgress:
    directory = _artifact_directory(artifact_directory, ignored_root=ignored_root)
    directory_owner: _OwnedFileDescriptor | None = None
    mutation_started = False
    active_error: BaseException | None = None
    try:
        retained_attempt.__post_init__()
        directory_owner = _open_owner_only_artifact_directory(
            directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        with _locked_attempt_slot(
            directory_descriptor,
            exclusive=True,
        ) as (slot_descriptor, names):
            if names != frozenset({POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME}):
                raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                    "trusted-time graceful-stop progress retention is unconfirmed"
                )
            slot_encoded, slot_identity = _read_descriptor(
                directory_descriptor,
                slot_descriptor,
                file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
            )
            observed_attempt = _attempt_receipt(
                record=decode_post_enrollment_graceful_stop_attempt_bytes(slot_encoded),
                artifact_directory=directory,
                encoded=slot_encoded,
                file_identity=slot_identity,
            )
            if not _same_attempt_receipt(retained_attempt, observed_attempt):
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop exact attempt receipt is unavailable"
                )
            record = _new_progress_record(observed_attempt.record)
            encoded = record.encoded
            file_name = _progress_file_name(record.record_sha256)
            mutation_started = True
            observed, file_identity = _publish_staged_file(
                directory_descriptor,
                staging_file_name=POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME,
                final_file_name=file_name,
                encoded=encoded,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
            )
            expected_names = frozenset(
                {
                    POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                    file_name,
                }
            )
            os.fsync(directory_descriptor)
            if observed != encoded or _lifecycle_names(directory_descriptor) != expected_names:
                raise OSError
            _rebind_exact_files(
                directory_descriptor,
                artifact_directory=directory,
                ignored_root=ignored_root,
                expected_names=expected_names,
                expected_files={
                    POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME: (
                        slot_encoded,
                        slot_identity,
                        MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
                    ),
                    file_name: (
                        observed,
                        file_identity,
                        MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
                    ),
                },
            )
            receipt = _progress_receipt(
                record=record,
                artifact_directory=directory,
                encoded=observed,
                file_identity=file_identity,
                attempt_slot_file_identity=slot_identity,
            )
        _run_cleanup_operations(None, (directory_owner.close,))
        return receipt
    except TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed as error:
        active_error = error
        raise
    except BaseException as error:
        active_error = error
        if mutation_started:
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop progress retention is unconfirmed"
            ) from None
        if isinstance(error, TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            raise
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop progress retention was rejected"
        ) from None
    finally:
        if directory_owner is not None:
            _run_cleanup_operations(active_error, (directory_owner.close,))


def _persist_outcome(
    retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopOutcome:
    directory = _artifact_directory(artifact_directory, ignored_root=ignored_root)
    directory_owner: _OwnedFileDescriptor | None = None
    mutation_started = False
    active_error: BaseException | None = None
    try:
        retained_attempt.__post_init__()
        retained_progress.__post_init__()
        directory_owner = _open_owner_only_artifact_directory(
            directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        with _locked_attempt_slot(
            directory_descriptor,
            exclusive=True,
        ) as (slot_descriptor, names):
            expected_progress_name = _progress_file_name(retained_progress.artifact_sha256)
            if names != frozenset(
                {
                    POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                    expected_progress_name,
                }
            ):
                raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                    "trusted-time graceful-stop outcome retention is unconfirmed"
                )
            slot_encoded, slot_identity = _read_descriptor(
                directory_descriptor,
                slot_descriptor,
                file_name=POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
            )
            observed_attempt = _attempt_receipt(
                record=decode_post_enrollment_graceful_stop_attempt_bytes(slot_encoded),
                artifact_directory=directory,
                encoded=slot_encoded,
                file_identity=slot_identity,
            )
            progress_encoded, progress_identity = _read_named_file(
                directory_descriptor,
                file_name=expected_progress_name,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
            )
            observed_progress = _progress_receipt(
                record=decode_post_enrollment_graceful_stop_progress_bytes(progress_encoded),
                artifact_directory=directory,
                encoded=progress_encoded,
                file_identity=progress_identity,
                attempt_slot_file_identity=slot_identity,
            )
            if not _same_attempt_receipt(
                retained_attempt,
                observed_attempt,
            ) or not _same_progress_receipt(retained_progress, observed_progress):
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop exact progress identity is unavailable"
                )
            _validate_progress_binding(observed_attempt.record, observed_progress.record)
            record = _new_outcome_record(
                observed_attempt.record,
                observed_progress.record,
            )
            encoded = record.encoded
            outcome_file_name = _outcome_file_name(record.record_sha256)
            mutation_started = True
            observed, outcome_identity = _publish_staged_file(
                directory_descriptor,
                staging_file_name=POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME,
                final_file_name=outcome_file_name,
                encoded=encoded,
                maximum_bytes=MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES,
            )
            commit_encoded = _outcome_commit_bytes(record)
            observed_commit, commit_identity = _publish_staged_file(
                directory_descriptor,
                staging_file_name=(POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME),
                final_file_name=POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME,
                encoded=commit_encoded,
                maximum_bytes=_MAXIMUM_COMMIT_BYTES,
            )
            expected_names = frozenset(
                {
                    POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME,
                    expected_progress_name,
                    outcome_file_name,
                    POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME,
                }
            )
            os.fsync(directory_descriptor)
            if (
                observed != encoded
                or observed_commit != commit_encoded
                or _lifecycle_names(directory_descriptor) != expected_names
            ):
                raise OSError
            _rebind_exact_files(
                directory_descriptor,
                artifact_directory=directory,
                ignored_root=ignored_root,
                expected_names=expected_names,
                expected_files={
                    POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME: (
                        slot_encoded,
                        slot_identity,
                        MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES,
                    ),
                    expected_progress_name: (
                        progress_encoded,
                        progress_identity,
                        MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES,
                    ),
                    outcome_file_name: (
                        observed,
                        outcome_identity,
                        MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES,
                    ),
                    POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME: (
                        observed_commit,
                        commit_identity,
                        _MAXIMUM_COMMIT_BYTES,
                    ),
                },
            )
            receipt = _outcome_receipt(
                record=record,
                artifact_directory=directory,
                encoded=observed,
                file_identity=outcome_identity,
                attempt_slot_file_identity=slot_identity,
                progress_file_identity=progress_identity,
                commit_encoded=observed_commit,
                commit_file_identity=commit_identity,
            )
        _run_cleanup_operations(None, (directory_owner.close,))
        return receipt
    except TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed as error:
        active_error = error
        raise
    except BaseException as error:
        active_error = error
        if mutation_started:
            raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                "trusted-time graceful-stop outcome retention is unconfirmed"
            ) from None
        if isinstance(error, TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            raise
        raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
            "trusted-time graceful-stop outcome retention was rejected"
        ) from None
    finally:
        if directory_owner is not None:
            _run_cleanup_operations(active_error, (directory_owner.close,))


def load_retained_post_enrollment_graceful_stop_attempt(
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
    """Load the exact stable ordinal-zero record without granting authority."""

    attempt, _, _ = _load_chain(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return attempt


def load_retained_post_enrollment_graceful_stop_progress(
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopProgress:
    """Load the exact stable bridge-required checkpoint."""

    _, progress, _ = _load_chain(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    if progress is None:
        raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop progress evidence is unavailable"
        )
    return progress


def load_retained_post_enrollment_graceful_stop_outcome(
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentGracefulStopOutcome:
    """Load the exact committed recovery-only outcome."""

    _, _, outcome = _load_chain(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    if outcome is None:
        raise TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable(
            "trusted-time graceful-stop outcome evidence is unavailable"
        )
    return outcome


def revalidate_retained_post_enrollment_graceful_stop_attempt(
    retained: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    """Return true only while the exact attempt bytes, inode, and path persist."""

    try:
        observed = load_retained_post_enrollment_graceful_stop_attempt(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return _same_attempt_receipt(retained, observed)
    except Exception:
        return False


def revalidate_retained_post_enrollment_graceful_stop_progress(
    retained: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    """Return true only while the exact progress chain and inodes persist."""

    try:
        observed = load_retained_post_enrollment_graceful_stop_progress(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return _same_progress_receipt(retained, observed)
    except Exception:
        return False


def revalidate_retained_post_enrollment_graceful_stop_outcome(
    retained: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    """Return true only while the exact committed outcome chain persists."""

    try:
        observed = load_retained_post_enrollment_graceful_stop_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return _same_outcome_receipt(retained, observed)
    except Exception:
        return False


def _recovery_state(
    status: TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus,
    *,
    attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None = None,
    progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None = None,
    outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None = None,
) -> TrustedTimePostEnrollmentGracefulStopRecoveryState:
    return TrustedTimePostEnrollmentGracefulStopRecoveryState(
        status=status,
        attempt=attempt,
        progress=progress,
        outcome=outcome,
        _construction_capability=_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def inspect_post_enrollment_graceful_stop_recovery_state(
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> TrustedTimePostEnrollmentGracefulStopRecoveryState:
    """Classify stable durable evidence; never infer retry or continuation."""

    try:
        directory = _artifact_directory(artifact_directory, ignored_root=ignored_root)
    except Exception:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    except OSError:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    if not stat.S_ISDIR(metadata.st_mode):
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_locked = False
    active_error: BaseException | None = None
    unreserved_state: TrustedTimePostEnrollmentGracefulStopRecoveryState | None = None
    try:
        try:
            directory_owner = _open_owner_only_artifact_directory(
                directory,
                ignored_root=ignored_root,
                create=False,
            )
            directory_descriptor = directory_owner.fileno()
            fcntl.flock(directory_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            directory_locked = True
            names = _lifecycle_names(directory_descriptor)
            rebound_owner: _OwnedFileDescriptor | None = None
            rebound_error: BaseException | None = None
            try:
                rebound_owner = _open_owner_only_artifact_directory(
                    directory,
                    ignored_root=ignored_root,
                    create=False,
                )
                if (
                    _stable_file_identity(os.fstat(rebound_owner.fileno()))
                    != _stable_file_identity(os.fstat(directory_descriptor))
                    or _lifecycle_names(rebound_owner.fileno()) != names
                ):
                    raise OSError
            except BaseException as error:
                rebound_error = error
                raise
            finally:
                if rebound_owner is not None:
                    _run_cleanup_operations(rebound_error, (rebound_owner.close,))
            if not names:
                unreserved_state = _recovery_state(
                    TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.UNRESERVED
                )
        except BaseException as error:
            active_error = error
            raise
        finally:
            cleanup_operations: list[Callable[[], None]] = []
            if directory_owner is not None:
                if directory_locked:
                    directory_locked = False
                    cleanup_operations.append(
                        lambda: fcntl.flock(directory_owner.fileno(), fcntl.LOCK_UN)
                    )
                cleanup_operations.append(directory_owner.close)
            _run_cleanup_operations(active_error, tuple(cleanup_operations))
    except Exception:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    if unreserved_state is not None:
        return unreserved_state
    try:
        attempt, progress, outcome = _load_chain(
            artifact_directory=directory,
            ignored_root=ignored_root,
        )
    except Exception:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
    if outcome is not None:
        return _recovery_state(
            TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.TERMINAL_OUTCOME_RETAINED,
            attempt=attempt,
            progress=progress,
            outcome=outcome,
        )
    return _recovery_state(
        TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED,
        attempt=attempt,
        progress=progress,
    )


class _RepositorySnapshot(NamedTuple):
    ignored_root: Path
    owner_pid: int
    owner_thread: threading.Thread
    owner_thread_id: int
    attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None
    progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None
    outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None
    closed: bool
    generation: object


def _build_repository_state_registry() -> tuple[object, object, object, object, object]:
    registry_pid = os.getpid()
    entries: WeakKeyDictionary[object, tuple[object, ...]] = WeakKeyDictionary()

    def register(
        repository: object,
        *,
        ignored_root: Path,
        owner_pid: int,
        owner_thread: threading.Thread,
        owner_thread_id: int,
    ) -> None:
        if (
            type(repository) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
            or type(ignored_root) is not type(Path())
            or type(owner_pid) is not int
            or owner_pid != registry_pid
            or owner_thread is not threading.current_thread()
            or type(owner_thread_id) is not int
            or owner_thread_id != threading.get_ident()
            or os.getpid() != registry_pid
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle registry is unavailable after fork"
            )
        with _PROCESS_LOCK:
            if repository in entries:
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop lifecycle repository is unavailable"
                )
            entries[repository] = (
                ignored_root,
                owner_pid,
                owner_thread,
                owner_thread_id,
                None,
                None,
                None,
                False,
                object(),
            )

    def resolve(repository: object) -> _RepositorySnapshot:
        if (
            type(repository) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
            or os.getpid() != registry_pid
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle registry is unavailable after fork"
            )
        with _PROCESS_LOCK:
            entry = entries.get(repository)
        if entry is None:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle repository is unavailable"
            )
        return _RepositorySnapshot(
            cast(Path, entry[0]),
            cast(int, entry[1]),
            cast(threading.Thread, entry[2]),
            cast(int, entry[3]),
            cast(RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None, entry[4]),
            cast(RetainedTrustedTimePostEnrollmentGracefulStopProgress | None, entry[5]),
            cast(RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None, entry[6]),
            cast(bool, entry[7]),
            entry[8],
        )

    def transition(
        repository: object,
        expected: _RepositorySnapshot,
        *,
        attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None,
        progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None,
        outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None,
        closed: bool,
    ) -> _RepositorySnapshot:
        if (
            type(repository) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
            or os.getpid() != registry_pid
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle registry is unavailable after fork"
            )
        if (
            type(expected) is not _RepositorySnapshot
            or type(expected.ignored_root) is not type(Path())
            or type(expected.owner_pid) is not int
            or expected.owner_thread is not threading.current_thread()
            or type(expected.owner_thread_id) is not int
            or (
                expected.attempt is not None
                and type(expected.attempt)
                is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
            )
            or (
                expected.progress is not None
                and type(expected.progress)
                is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
            )
            or (
                expected.outcome is not None
                and type(expected.outcome)
                is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
            )
            or type(expected.closed) is not bool
            or (
                attempt is not None
                and type(attempt) is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
            )
            or (
                progress is not None
                and type(progress) is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
            )
            or (
                outcome is not None
                and type(outcome) is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
            )
            or type(closed) is not bool
        ):
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle repository state changed"
            )
        with _PROCESS_LOCK:
            current = entries.get(repository)
            if (
                current is None
                or current[8] is not expected.generation
                or current[0] != expected.ignored_root
                or current[1] != expected.owner_pid
                or current[2] is not expected.owner_thread
                or current[3] != expected.owner_thread_id
                or current[4] is not expected.attempt
                or current[5] is not expected.progress
                or current[6] is not expected.outcome
                or current[7] is not expected.closed
            ):
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop lifecycle repository state changed"
                )
            generation = object()
            entries[repository] = (
                current[0],
                current[1],
                current[2],
                current[3],
                attempt,
                progress,
                outcome,
                closed,
                generation,
            )
            return _RepositorySnapshot(
                current[0],
                current[1],
                current[2],
                current[3],
                attempt,
                progress,
                outcome,
                closed,
                generation,
            )

    def burn(repository: object, primary_error: BaseException | None = None) -> None:
        registry_error: BaseException | None = None
        try:
            if (
                type(repository) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
                or os.getpid() != registry_pid
            ):
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop lifecycle registry is unavailable after fork"
                )
            with _PROCESS_LOCK:
                entry = entries.get(repository)
                if entry is None:
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository is unavailable"
                    )
                entries[repository] = (
                    entry[0],
                    entry[1],
                    entry[2],
                    entry[3],
                    entry[4],
                    entry[5],
                    entry[6],
                    True,
                    object(),
                )
        except BaseException as error:
            registry_error = error
        try:
            object.__setattr__(repository, "_closed", True)
        except BaseException as error:
            if registry_error is None:
                registry_error = error
        if primary_error is None and registry_error is not None:
            raise registry_error

    def cardinality() -> int:
        if os.getpid() != registry_pid:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle registry is unavailable after fork"
            )
        with _PROCESS_LOCK:
            return len(entries)

    return register, resolve, transition, burn, cardinality


(
    _register_repository_state_untyped,
    _registered_repository_state_untyped,
    _replace_repository_state_untyped,
    _burn_repository_untyped,
    _repository_state_registry_cardinality_untyped,
) = _build_repository_state_registry()

_register_repository_state = cast(Any, _register_repository_state_untyped)
_registered_repository_state = cast(Any, _registered_repository_state_untyped)
_replace_repository_state = cast(Any, _replace_repository_state_untyped)
_burn_repository = cast(Any, _burn_repository_untyped)
_repository_state_registry_cardinality = cast(
    Any,
    _repository_state_registry_cardinality_untyped,
)


class _TrustedTimePostEnrollmentGracefulStopLifecycleRepository:
    """Process/thread-sealed one-shot writer with no production construction."""

    __slots__ = (
        "__weakref__",
        "_attempt",
        "_closed",
        "_ignored_root",
        "_outcome",
        "_owner_pid",
        "_owner_thread",
        "_owner_thread_id",
        "_progress",
        "_sealed_configuration",
        "_sealed_state",
    )

    def __init__(
        self,
        *,
        ignored_root: Path,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _REPOSITORY_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle repository is unavailable"
            )
        if type(ignored_root) is not type(Path()) or not ignored_root.is_absolute():
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle root is invalid"
            )
        root = Path(os.path.abspath(ignored_root))
        if root != ignored_root:
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle root is invalid"
            )
        self._ignored_root = root
        self._owner_pid = os.getpid()
        self._owner_thread = threading.current_thread()
        self._owner_thread_id = threading.get_ident()
        self._attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None = None
        self._progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress | None = None
        self._outcome: RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None = None
        self._closed = False
        self._sealed_configuration = (
            type(self),
            self._ignored_root,
            self._owner_pid,
            self._owner_thread,
            self._owner_thread_id,
        )
        self._sealed_state: tuple[
            RetainedTrustedTimePostEnrollmentGracefulStopAttempt | None,
            RetainedTrustedTimePostEnrollmentGracefulStopProgress | None,
            RetainedTrustedTimePostEnrollmentGracefulStopOutcome | None,
            bool,
        ] = (None, None, None, False)

    def _check_context(self) -> _RepositorySnapshot:
        try:
            if (
                type(self) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
                or type(self._owner_pid) is not int
                or self._owner_thread is not threading.current_thread()
                or type(self._owner_thread_id) is not int
                or os.getpid() != self._owner_pid
                or threading.get_ident() != self._owner_thread_id
            ):
                raise ValueError
            untrusted_state = _registered_repository_state(self)
            if type(untrusted_state) is not _RepositorySnapshot:
                raise ValueError
            state = untrusted_state
            if (
                type(state.ignored_root) is not type(Path())
                or not state.ignored_root.is_absolute()
                or type(state.owner_pid) is not int
                or state.owner_pid <= 0
                or state.owner_thread is not threading.current_thread()
                or type(state.owner_thread_id) is not int
                or state.owner_thread_id <= 0
                or os.getpid() != state.owner_pid
                or threading.get_ident() != state.owner_thread_id
                or (
                    state.attempt is not None
                    and type(state.attempt)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                )
                or (
                    state.progress is not None
                    and type(state.progress)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                )
                or (
                    state.outcome is not None
                    and type(state.outcome)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                )
                or type(state.closed) is not bool
                or type(self._ignored_root) is not type(Path())
                or type(self._closed) is not bool
                or type(self._sealed_configuration) is not tuple
                or len(self._sealed_configuration) != 5
                or self._sealed_configuration[0] is not type(self)
                or type(self._sealed_configuration[1]) is not type(Path())
                or type(self._sealed_configuration[2]) is not int
                or self._sealed_configuration[3] is not threading.current_thread()
                or type(self._sealed_configuration[4]) is not int
                or type(self._sealed_state) is not tuple
                or len(self._sealed_state) != 4
                or (
                    self._sealed_state[0] is not None
                    and type(self._sealed_state[0])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                )
                or (
                    self._sealed_state[1] is not None
                    and type(self._sealed_state[1])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                )
                or (
                    self._sealed_state[2] is not None
                    and type(self._sealed_state[2])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                )
                or type(self._sealed_state[3]) is not bool
            ):
                raise ValueError
            valid_order = (
                (state.attempt is None and state.progress is None and state.outcome is None)
                or (state.attempt is not None and state.progress is None and state.outcome is None)
                or (
                    state.attempt is not None
                    and state.progress is not None
                    and state.outcome is None
                )
                or (
                    state.attempt is not None
                    and state.progress is not None
                    and state.outcome is not None
                    and state.closed
                )
            )
            if state.attempt is not None:
                state.attempt.__post_init__()
                if state.attempt.artifact_path.parent != state.ignored_root / "trusted-time":
                    raise ValueError
            if state.progress is not None:
                state.progress.__post_init__()
                if (
                    state.attempt is None
                    or state.progress.attempt_slot_file_identity != state.attempt.file_identity
                    or state.progress.artifact_path.parent != state.attempt.artifact_path.parent
                ):
                    raise ValueError
                _validate_progress_binding(state.attempt.record, state.progress.record)
            if state.outcome is not None:
                state.outcome.__post_init__()
                if (
                    state.attempt is None
                    or state.progress is None
                    or state.outcome.attempt_slot_file_identity != state.attempt.file_identity
                    or state.outcome.progress_file_identity != state.progress.file_identity
                    or state.outcome.artifact_path.parent != state.attempt.artifact_path.parent
                ):
                    raise ValueError
                _validate_outcome_binding(
                    state.attempt.record,
                    state.progress.record,
                    state.outcome.record,
                )
            valid = (
                self._ignored_root == state.ignored_root
                and self._owner_pid == state.owner_pid
                and self._owner_thread is state.owner_thread
                and self._owner_thread_id == state.owner_thread_id
                and self._attempt is state.attempt
                and self._progress is state.progress
                and self._outcome is state.outcome
                and self._closed is state.closed
                and self._sealed_configuration[0] is type(self)
                and self._sealed_configuration[1] == state.ignored_root
                and self._sealed_configuration[2] == state.owner_pid
                and self._sealed_configuration[3] is state.owner_thread
                and self._sealed_configuration[4] == state.owner_thread_id
                and self._sealed_state
                == (state.attempt, state.progress, state.outcome, state.closed)
                and valid_order
                and not state.closed
            )
        except BaseException as error:
            _burn_repository(self, error)
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle repository context is unavailable"
            ) from None
        if not valid:
            _burn_repository(self)
            raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                "trusted-time graceful-stop lifecycle repository context is unavailable"
            )
        return state

    def _reserve_attempt(
        self,
        *,
        decision: TrustedTimePostEnrollmentGracefulStopDecision,
        envelope: TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
        verification: (TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification),
    ) -> RetainedTrustedTimePostEnrollmentGracefulStopAttempt:
        self._check_context()
        with _PROCESS_LOCK:
            state = self._check_context()
            if state.attempt is not None:
                _burn_repository(self)
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop attempt reservation cannot be replayed"
                )
            record = _new_attempt_record(
                decision=decision,
                envelope=envelope,
                verification=verification,
            )
            ignored_root = state.ignored_root
            artifact_directory = ignored_root / "trusted-time"
            transition_started = False
            try:
                transition_started = True
                retained = _persist_attempt(
                    record,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
                if self._check_context().generation is not state.generation:
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                _replace_repository_state(
                    self,
                    state,
                    attempt=retained,
                    progress=None,
                    outcome=None,
                    closed=False,
                )
                self._attempt = retained
                self._sealed_state = (retained, None, None, False)
                return retained
            except TrustedTimePostEnrollmentGracefulStopAttemptConsumed as error:
                _burn_repository(self, error)
                raise
            except BaseException as error:
                _burn_repository(self, error)
                if transition_started and not isinstance(
                    error,
                    TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed,
                ):
                    raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                        "trusted-time graceful-stop attempt retention is unconfirmed"
                    ) from None
                raise

    def _retain_bridge_required_progress(
        self,
        retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    ) -> RetainedTrustedTimePostEnrollmentGracefulStopProgress:
        self._check_context()
        with _PROCESS_LOCK:
            state = self._check_context()
            if (
                state.attempt is None
                or retained_attempt is not state.attempt
                or state.progress is not None
            ):
                _burn_repository(self)
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop progress identity is unavailable"
                )
            ignored_root = state.ignored_root
            artifact_directory = ignored_root / "trusted-time"
            transition_started = False
            try:
                transition_started = True
                retained = _persist_progress(
                    retained_attempt,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
                if self._check_context().generation is not state.generation:
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                _replace_repository_state(
                    self,
                    state,
                    attempt=state.attempt,
                    progress=retained,
                    outcome=None,
                    closed=False,
                )
                self._progress = retained
                self._sealed_state = (state.attempt, retained, None, False)
                return retained
            except BaseException as error:
                _burn_repository(self, error)
                if transition_started and not isinstance(
                    error,
                    TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed,
                ):
                    raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                        "trusted-time graceful-stop progress retention is unconfirmed"
                    ) from None
                raise

    def _retain_recovery_required_outcome(
        self,
        retained_attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
        retained_progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    ) -> RetainedTrustedTimePostEnrollmentGracefulStopOutcome:
        self._check_context()
        with _PROCESS_LOCK:
            state = self._check_context()
            if (
                state.attempt is None
                or state.progress is None
                or retained_attempt is not state.attempt
                or retained_progress is not state.progress
            ):
                _burn_repository(self)
                raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                    "trusted-time graceful-stop outcome identity is unavailable"
                )
            ignored_root = state.ignored_root
            artifact_directory = ignored_root / "trusted-time"
            transition_started = False
            try:
                transition_started = True
                untrusted_transition_state = _replace_repository_state(
                    self,
                    state,
                    attempt=state.attempt,
                    progress=state.progress,
                    outcome=None,
                    closed=True,
                )
                if type(untrusted_transition_state) is not _RepositorySnapshot:
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                transition_state = untrusted_transition_state
                self._closed = True
                self._sealed_state = (
                    state.attempt,
                    state.progress,
                    None,
                    True,
                )
                retained = _persist_outcome(
                    retained_attempt,
                    retained_progress,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
                untrusted_observed_state = _registered_repository_state(self)
                if (
                    type(untrusted_observed_state) is not _RepositorySnapshot
                    or type(untrusted_observed_state.ignored_root) is not type(Path())
                    or type(untrusted_observed_state.owner_pid) is not int
                    or untrusted_observed_state.owner_thread is not threading.current_thread()
                    or type(untrusted_observed_state.owner_thread_id) is not int
                    or type(untrusted_observed_state.attempt)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                    or type(untrusted_observed_state.progress)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                    or untrusted_observed_state.outcome is not None
                    or type(untrusted_observed_state.closed) is not bool
                ):
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                observed_state = untrusted_observed_state
                if (
                    observed_state.generation is not transition_state.generation
                    or observed_state.ignored_root != ignored_root
                    or observed_state.owner_pid != os.getpid()
                    or observed_state.owner_thread is not threading.current_thread()
                    or observed_state.owner_thread_id != threading.get_ident()
                    or observed_state.attempt is not state.attempt
                    or observed_state.progress is not state.progress
                    or observed_state.closed is not True
                    or self._attempt is not state.attempt
                    or self._progress is not state.progress
                    or self._outcome is not None
                    or self._closed is not True
                    or type(self._sealed_state) is not tuple
                    or len(self._sealed_state) != 4
                    or self._sealed_state[0] is not state.attempt
                    or self._sealed_state[1] is not state.progress
                    or self._sealed_state[2] is not None
                    or self._sealed_state[3] is not True
                ):
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                untrusted_terminal_state = _replace_repository_state(
                    self,
                    transition_state,
                    attempt=state.attempt,
                    progress=state.progress,
                    outcome=retained,
                    closed=True,
                )
                if type(untrusted_terminal_state) is not _RepositorySnapshot:
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                terminal_state = untrusted_terminal_state
                self._outcome = retained
                self._sealed_state = (
                    state.attempt,
                    state.progress,
                    retained,
                    True,
                )
                untrusted_terminal_state = _registered_repository_state(self)
                if (
                    type(untrusted_terminal_state) is not _RepositorySnapshot
                    or type(untrusted_terminal_state.ignored_root) is not type(Path())
                    or type(untrusted_terminal_state.owner_pid) is not int
                    or untrusted_terminal_state.owner_thread is not threading.current_thread()
                    or type(untrusted_terminal_state.owner_thread_id) is not int
                    or type(untrusted_terminal_state.attempt)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                    or type(untrusted_terminal_state.progress)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                    or type(untrusted_terminal_state.outcome)
                    is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                    or type(untrusted_terminal_state.closed) is not bool
                    or type(self) is not _TrustedTimePostEnrollmentGracefulStopLifecycleRepository
                    or type(self._ignored_root) is not type(Path())
                    or type(self._owner_pid) is not int
                    or self._owner_thread is not threading.current_thread()
                    or type(self._owner_thread_id) is not int
                    or type(self._closed) is not bool
                    or type(self._sealed_configuration) is not tuple
                    or len(self._sealed_configuration) != 5
                    or self._sealed_configuration[0] is not type(self)
                    or type(self._sealed_configuration[1]) is not type(Path())
                    or type(self._sealed_configuration[2]) is not int
                    or self._sealed_configuration[3] is not threading.current_thread()
                    or type(self._sealed_configuration[4]) is not int
                    or type(self._sealed_state) is not tuple
                    or len(self._sealed_state) != 4
                    or type(self._sealed_state[0])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopAttempt
                    or type(self._sealed_state[1])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopProgress
                    or type(self._sealed_state[2])
                    is not RetainedTrustedTimePostEnrollmentGracefulStopOutcome
                    or type(self._sealed_state[3]) is not bool
                ):
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                observed_terminal_state = untrusted_terminal_state
                if (
                    observed_terminal_state.generation is not terminal_state.generation
                    or observed_terminal_state.ignored_root != ignored_root
                    or observed_terminal_state.owner_pid != os.getpid()
                    or observed_terminal_state.owner_thread is not threading.current_thread()
                    or observed_terminal_state.owner_thread_id != threading.get_ident()
                    or observed_terminal_state.attempt is not state.attempt
                    or observed_terminal_state.progress is not state.progress
                    or observed_terminal_state.outcome is not retained
                    or observed_terminal_state.closed is not True
                    or self._ignored_root != ignored_root
                    or self._owner_pid != observed_terminal_state.owner_pid
                    or self._owner_thread is not observed_terminal_state.owner_thread
                    or self._owner_thread_id != observed_terminal_state.owner_thread_id
                    or self._attempt is not state.attempt
                    or self._progress is not state.progress
                    or self._outcome is not retained
                    or self._closed is not True
                    or self._sealed_configuration[0] is not type(self)
                    or self._sealed_configuration[1] != ignored_root
                    or self._sealed_configuration[2] != observed_terminal_state.owner_pid
                    or self._sealed_configuration[3] is not observed_terminal_state.owner_thread
                    or self._sealed_configuration[4] != observed_terminal_state.owner_thread_id
                    or self._sealed_state[0] is not state.attempt
                    or self._sealed_state[1] is not state.progress
                    or self._sealed_state[2] is not retained
                    or self._sealed_state[3] is not True
                ):
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                state.attempt.__post_init__()
                state.progress.__post_init__()
                retained.__post_init__()
                if (
                    state.attempt.artifact_path.parent != artifact_directory
                    or state.progress.artifact_path.parent != artifact_directory
                    or retained.artifact_path.parent != artifact_directory
                    or state.progress.attempt_slot_file_identity != state.attempt.file_identity
                    or retained.attempt_slot_file_identity != state.attempt.file_identity
                    or retained.progress_file_identity != state.progress.file_identity
                ):
                    raise TrustedTimePostEnrollmentGracefulStopLifecycleRejected(
                        "trusted-time graceful-stop lifecycle repository state changed"
                    )
                _validate_progress_binding(state.attempt.record, state.progress.record)
                _validate_outcome_binding(
                    state.attempt.record,
                    state.progress.record,
                    retained.record,
                )
                return retained
            except BaseException as error:
                _burn_repository(self, error)
                if transition_started and not isinstance(
                    error,
                    TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed,
                ):
                    raise TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed(
                        "trusted-time graceful-stop outcome retention is unconfirmed"
                    ) from None
                raise

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: object) -> Never:
        _cannot_copy()


def _build_post_enrollment_graceful_stop_lifecycle_repository(
    *,
    ignored_root: Path,
) -> _TrustedTimePostEnrollmentGracefulStopLifecycleRepository:
    """Build the dormant process-private test seam; no production caller exists."""

    repository = _TrustedTimePostEnrollmentGracefulStopLifecycleRepository(
        ignored_root=ignored_root,
        _construction_capability=_REPOSITORY_CONSTRUCTION_CAPABILITY,
    )
    _register_repository_state(
        repository,
        ignored_root=repository._ignored_root,
        owner_pid=repository._owner_pid,
        owner_thread=repository._owner_thread,
        owner_thread_id=repository._owner_thread_id,
    )
    return repository


__all__ = [
    "MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_BYTES",
    "MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_FILE_NAME_BYTES",
    "MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_ENTRIES",
    "MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_BYTES",
    "MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME",
    "POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_PREFIX",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_SUFFIX",
    "POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME",
    "POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX",
    "POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME",
    "POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_TRANSCRIPT_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_REASON",
    "POST_ENROLLMENT_GRACEFUL_STOP_RETAINED_OUTCOME_STATUS",
    "RetainedTrustedTimePostEnrollmentGracefulStopAttempt",
    "RetainedTrustedTimePostEnrollmentGracefulStopOutcome",
    "RetainedTrustedTimePostEnrollmentGracefulStopProgress",
    "TrustedTimePostEnrollmentGracefulStopAttemptConsumed",
    "TrustedTimePostEnrollmentGracefulStopAttemptRecord",
    "TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable",
    "TrustedTimePostEnrollmentGracefulStopLifecycleRejected",
    "TrustedTimePostEnrollmentGracefulStopOutcomeRecord",
    "TrustedTimePostEnrollmentGracefulStopProgressPhase",
    "TrustedTimePostEnrollmentGracefulStopProgressRecord",
    "TrustedTimePostEnrollmentGracefulStopRecoveryState",
    "TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus",
    "TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed",
    "canonical_post_enrollment_graceful_stop_attempt_bytes",
    "canonical_post_enrollment_graceful_stop_outcome_bytes",
    "canonical_post_enrollment_graceful_stop_progress_bytes",
    "decode_post_enrollment_graceful_stop_attempt_bytes",
    "decode_post_enrollment_graceful_stop_outcome_bytes",
    "decode_post_enrollment_graceful_stop_progress_bytes",
    "inspect_post_enrollment_graceful_stop_recovery_state",
    "load_retained_post_enrollment_graceful_stop_attempt",
    "load_retained_post_enrollment_graceful_stop_outcome",
    "load_retained_post_enrollment_graceful_stop_progress",
    "revalidate_retained_post_enrollment_graceful_stop_attempt",
    "revalidate_retained_post_enrollment_graceful_stop_outcome",
    "revalidate_retained_post_enrollment_graceful_stop_progress",
]
