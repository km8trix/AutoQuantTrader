"""Canonical classification-only recovery evidence for lifecycle v2.

This module defines signed, non-effecting recovery-classification bytes.  It
does not load a key, authenticate a signature, publish an artifact, resume an
effect, or grant graceful-stop authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Self, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_MAXIMUM_ENTRIES,
    LIFECYCLE_V2_OPERATION_BUDGET_NS,
    LIFECYCLE_V2_SERVICE,
    MAXIMUM_SIGNED_INTEGER,
    NORMAL_STAGE_BY_ORDINAL,
    FrozenJsonObject,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
)

RECOVERY_CLASSIFICATION_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-recovery-classification-envelope-v1"
)
RECOVERY_CLASSIFICATION_SIGNATURE_DOMAIN = (
    "AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1"
)
RECOVERY_CLASSIFICATION_MAXIMUM_BYTES = 64 * 1_024

RECOVERY_CLASSIFICATION_REASON_CODES = frozenset(
    {
        "call_or_result_ambiguous",
        "pre_effect_reauthentication_unconfirmed",
        "supervisor_stop_unconfirmed",
        "source_stop_unconfirmed",
        "supervisor_remove_unconfirmed",
        "source_remove_unconfirmed",
        "network_remove_unconfirmed",
        "volume_preservation_unconfirmed",
        "post_teardown_reauthentication_unconfirmed",
        "transport_cleanup_unconfirmed",
        "terminal_cleanup_unconfirmed",
        "outcome_commit_unconfirmed",
        "deadline_expired",
        "lock_lost",
        "fork_detected",
    }
)

_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "root_sha256",
        "admission_started_boottime_ns",
        "operation_deadline_boottime_ns",
        "transcript_sha256",
        "last_ordinal",
        "last_stage",
        "reason_code",
        "transport_authority_manifest_sha256",
        "key_generation",
        "recovery_key_id",
        "operator_nonce_base64",
        "issued_at_utc",
        "signature_ed25519_base64",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")

_PRODUCTION_RECOVERY_INTENT_CAPABILITY = object()
_FAKE_RECOVERY_INTENT_CAPABILITY = object()
_PRODUCTION_AUTHENTICATED_RECOVERY_TYPE = (
    "packages.adapters.trusted_time.graceful_stop_v2_ed25519",
    "AuthenticatedLifecycleV2RecoveryClassificationEnvelope",
)
_CONSUMED_RECOVERY_NONCES: set[tuple[int, str, str]] = set()
_CONSUMED_RECOVERY_NONCES_LOCK = threading.Lock()


def _require_fields(value: dict[str, object]) -> None:
    if frozenset(value) != _FIELDS:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery classification field set is not exact"
        )


def _require_identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not a bounded identifier")
    return value


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not lowercase SHA-256")
    return value


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


def _require_base64(value: object, name: str, *, exact_length: int) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TrustedTimeGracefulStopV2Rejected(f"{name} is not canonical base64") from error
    if (
        len(decoded) != exact_length
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise TrustedTimeGracefulStopV2Rejected(f"{name} has the wrong canonical bytes")
    return decoded


def _require_prefix_stage(ordinal: int, stage_value: object) -> LifecycleV2Stage:
    try:
        stage = LifecycleV2Stage(stage_value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery classification last stage is unknown"
        ) from error
    expected = NORMAL_STAGE_BY_ORDINAL.get(ordinal)
    if ordinal == 2 and stage is LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED:
        return stage
    if expected is None or stage is not expected:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery classification last stage does not match its ordinal"
        )
    return stage


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2RecoveryClassificationEnvelope:
    """Structurally exact recovery-key-signed classification bytes."""

    fields: FrozenJsonObject
    operator_nonce: bytes
    signature: bytes

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("recovery classification envelopes require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields)
        if (
            fields["contract_version"] != RECOVERY_CLASSIFICATION_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["status"] != "recovery_classification_requested"
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification discriminator is invalid"
            )
        _require_identifier(fields["environment"], "environment")
        _require_identifier(
            fields["graceful_stop_operation_id"], "graceful_stop_operation_id"
        )
        _require_sha256(fields["root_sha256"], "root_sha256")
        start = _require_int(
            fields["admission_started_boottime_ns"],
            "admission_started_boottime_ns",
        )
        deadline = _require_int(
            fields["operation_deadline_boottime_ns"],
            "operation_deadline_boottime_ns",
        )
        if (
            start > MAXIMUM_SIGNED_INTEGER - LIFECYCLE_V2_OPERATION_BUDGET_NS
            or deadline != start + LIFECYCLE_V2_OPERATION_BUDGET_NS
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification operation deadline is not exact"
            )
        _require_sha256(fields["transcript_sha256"], "transcript_sha256")
        last_ordinal = _require_int(
            fields["last_ordinal"],
            "last_ordinal",
            minimum=1,
            maximum=min(22, LIFECYCLE_V2_MAXIMUM_ENTRIES - 1),
        )
        _require_prefix_stage(last_ordinal, fields["last_stage"])
        if (
            type(fields["reason_code"]) is not str
            or fields["reason_code"] not in RECOVERY_CLASSIFICATION_REASON_CODES
        ):
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification reason is not allowlisted"
            )
        _require_sha256(
            fields["transport_authority_manifest_sha256"],
            "transport_authority_manifest_sha256",
        )
        _require_int(fields["key_generation"], "key_generation", minimum=1)
        _require_identifier(fields["recovery_key_id"], "recovery_key_id")
        nonce = _require_base64(
            fields["operator_nonce_base64"],
            "operator_nonce_base64",
            exact_length=32,
        )
        if type(fields["issued_at_utc"]) is not str or _UTC.fullmatch(
            fields["issued_at_utc"]
        ) is None:
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification audit time is not canonical UTC"
            )
        signature = _require_base64(
            fields["signature_ed25519_base64"],
            "signature_ed25519_base64",
            exact_length=64,
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "operator_nonce", nonce)
        object.__setattr__(result, "signature", signature)
        if len(result.encoded) > RECOVERY_CLASSIFICATION_MAXIMUM_BYTES:
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification envelope is too large"
            )
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def unsigned_encoded(self) -> bytes:
        fields = self.to_dict()
        fields.pop("signature_ed25519_base64")
        return canonical_v2_json_bytes(
            fields,
            maximum_bytes=RECOVERY_CLASSIFICATION_MAXIMUM_BYTES,
        )

    @property
    def signature_input(self) -> bytes:
        return (
            RECOVERY_CLASSIFICATION_SIGNATURE_DOMAIN.encode("ascii")
            + b"\0"
            + self.unsigned_encoded
        )

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(
            self.to_dict(),
            maximum_bytes=RECOVERY_CLASSIFICATION_MAXIMUM_BYTES,
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    @property
    def operator_nonce_sha256(self) -> str:
        return hashlib.sha256(self.operator_nonce).hexdigest()

    @property
    def environment(self) -> str:
        return self.to_dict()["environment"]  # type: ignore[return-value]

    @property
    def graceful_stop_operation_id(self) -> str:
        return self.to_dict()["graceful_stop_operation_id"]  # type: ignore[return-value]

    @property
    def root_sha256(self) -> str:
        return self.to_dict()["root_sha256"]  # type: ignore[return-value]

    @property
    def transcript_sha256(self) -> str:
        return self.to_dict()["transcript_sha256"]  # type: ignore[return-value]

    @property
    def last_ordinal(self) -> int:
        return self.to_dict()["last_ordinal"]  # type: ignore[return-value]

    @property
    def last_stage(self) -> LifecycleV2Stage:
        return LifecycleV2Stage(cast(str, self.to_dict()["last_stage"]))

    @property
    def reason_code(self) -> str:
        return self.to_dict()["reason_code"]  # type: ignore[return-value]

    @property
    def transport_authority_manifest_sha256(self) -> str:
        return self.to_dict()["transport_authority_manifest_sha256"]  # type: ignore[return-value]

    @property
    def key_generation(self) -> int:
        return self.to_dict()["key_generation"]  # type: ignore[return-value]

    @property
    def recovery_key_id(self) -> str:
        return self.to_dict()["recovery_key_id"]  # type: ignore[return-value]

    @property
    def admission_started_boottime_ns(self) -> int:
        return self.to_dict()["admission_started_boottime_ns"]  # type: ignore[return-value]

    @property
    def operation_deadline_boottime_ns(self) -> int:
        return self.to_dict()["operation_deadline_boottime_ns"]  # type: ignore[return-value]


def decode_lifecycle_v2_recovery_classification_envelope(
    encoded: object,
) -> LifecycleV2RecoveryClassificationEnvelope:
    return LifecycleV2RecoveryClassificationEnvelope.capture(
        decode_canonical_v2_json_object(
            encoded,
            maximum_bytes=RECOVERY_CLASSIFICATION_MAXIMUM_BYTES,
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2AuthenticatedRecoveryIntent:
    """One exact, one-use recovery intent derived from authenticated bytes.

    The value is sealed by either the production Ed25519 adapter seam or the
    deliberately separate test-only seam.  Persistence may retain its record,
    but cannot manufacture or replace its signed classifier facts.
    """

    record: LifecycleV2ProgressRecord
    recovery_classification_envelope_sha256: str
    operator_nonce_sha256: str
    classified_transcript_sha256: str
    root_sha256: str
    _origin_pid: int
    _origin_thread: threading.Thread
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated recovery intents require one-use consumption")


_RecoveryEnvelopeUnwrapper = Callable[
    [object],
    tuple[LifecycleV2RecoveryClassificationEnvelope, str, str, str],
]


def _canonical_recovery_inputs(
    *,
    envelope: LifecycleV2RecoveryClassificationEnvelope,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
) -> tuple[
    LifecycleV2RecoveryClassificationEnvelope,
    LifecycleV2Root,
    LifecycleV2Transcript,
]:
    try:
        exact_envelope = decode_lifecycle_v2_recovery_classification_envelope(
            envelope.encoded
        )
        exact_root = decode_lifecycle_v2_root(root.encoded)
        exact_transcript = decode_lifecycle_v2_transcript(
            classified_transcript.encoded
        )
    except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery intent inputs are not canonical"
        ) from error
    if (
        exact_envelope != envelope
        or exact_root != root
        or exact_transcript != classified_transcript
        or len(exact_transcript.entries) < 2
        or exact_envelope.environment != exact_root.environment
        or exact_envelope.graceful_stop_operation_id
        != exact_root.graceful_stop_operation_id
        or exact_envelope.root_sha256 != exact_root.sha256
        or exact_envelope.admission_started_boottime_ns
        != exact_root.admission_started_boottime_ns
        or exact_envelope.operation_deadline_boottime_ns
        != exact_root.operation_deadline_boottime_ns
        or exact_envelope.transcript_sha256 != exact_transcript.sha256
        or exact_envelope.last_ordinal != exact_transcript.entries[-1].ordinal
        or exact_envelope.last_stage is not exact_transcript.entries[-1].stage
        or exact_transcript.environment != exact_root.environment
        or exact_transcript.graceful_stop_operation_id
        != exact_root.graceful_stop_operation_id
        or exact_transcript.root_sha256 != exact_root.sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery intent crossed its root or classified prefix"
        )
    return exact_envelope, exact_root, exact_transcript


def _derive_recovery_intent(
    *,
    envelope: LifecycleV2RecoveryClassificationEnvelope,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
    recorded_at_utc: str,
    capability: object,
) -> LifecycleV2AuthenticatedRecoveryIntent:
    exact_envelope, exact_root, exact_transcript = _canonical_recovery_inputs(
        envelope=envelope,
        root=root,
        classified_transcript=classified_transcript,
    )
    last_entry = exact_transcript.entries[-1]
    record = LifecycleV2ProgressRecord(
        graceful_stop_operation_id=exact_root.graceful_stop_operation_id,
        root_sha256=exact_root.sha256,
        ordinal=last_entry.ordinal + 1,
        stage=LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        predecessor_sha256=last_entry.record_artifact_sha256,
        effect_kind="recovery_classification",
        deadline_boottime_ns=exact_root.operation_deadline_boottime_ns,
        evidence=FrozenJsonObject.capture(
            {
                "recovery_classification_envelope_sha256": exact_envelope.sha256,
                "operator_nonce_sha256": exact_envelope.operator_nonce_sha256,
                "recovery_key_id": exact_envelope.recovery_key_id,
                "transport_authority_manifest_sha256": (
                    exact_envelope.transport_authority_manifest_sha256
                ),
                "classified_transcript_sha256": exact_transcript.sha256,
                "admission_started_boottime_ns": (
                    exact_root.admission_started_boottime_ns
                ),
                "operation_deadline_boottime_ns": (
                    exact_root.operation_deadline_boottime_ns
                ),
                "reason_code": exact_envelope.reason_code,
            }
        ),
        recorded_at_utc=recorded_at_utc,
    )
    result = object.__new__(LifecycleV2AuthenticatedRecoveryIntent)
    object.__setattr__(result, "record", record)
    object.__setattr__(
        result,
        "recovery_classification_envelope_sha256",
        exact_envelope.sha256,
    )
    object.__setattr__(
        result,
        "operator_nonce_sha256",
        exact_envelope.operator_nonce_sha256,
    )
    object.__setattr__(result, "classified_transcript_sha256", exact_transcript.sha256)
    object.__setattr__(result, "root_sha256", exact_root.sha256)
    object.__setattr__(result, "_origin_pid", os.getpid())
    object.__setattr__(result, "_origin_thread", threading.current_thread())
    object.__setattr__(result, "_capability", capability)
    return result


def _consume_authenticated_lifecycle_v2_recovery_classification_envelope(
    authenticated_envelope: object,
    *,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
    recorded_at_utc: str,
    unwrap: _RecoveryEnvelopeUnwrapper,
    capability: object,
) -> LifecycleV2AuthenticatedRecoveryIntent:
    """Private adapter seam for one authenticated, process-local consumption."""

    if capability is not _PRODUCTION_RECOVERY_INTENT_CAPABILITY:
        raise TrustedTimeGracefulStopV2Rejected(
            "production recovery-intent capability is invalid"
        )
    authenticated_type = type(authenticated_envelope)
    if (
        authenticated_type.__module__,
        authenticated_type.__qualname__,
    ) != _PRODUCTION_AUTHENTICATED_RECOVERY_TYPE:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery intent requires the exact adapter-authenticated type"
        )
    if not callable(unwrap):
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery-intent authenticated unwrapper is invalid"
        )
    try:
        unwrapped = unwrap(authenticated_envelope)
    except Exception as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "authenticated recovery classification cannot be consumed"
        ) from error
    if type(unwrapped) is not tuple or len(unwrapped) != 4:
        raise TrustedTimeGracefulStopV2Rejected(
            "recovery-intent unwrapper returned an invalid value"
        )
    envelope, wrapped_root_sha256, wrapped_transcript_sha256, wrapped_manifest_sha256 = (
        unwrapped
    )
    exact_envelope, exact_root, exact_transcript = _canonical_recovery_inputs(
        envelope=envelope,
        root=root,
        classified_transcript=classified_transcript,
    )
    if (
        wrapped_root_sha256 != exact_root.sha256
        or wrapped_transcript_sha256 != exact_transcript.sha256
        or wrapped_manifest_sha256
        != exact_envelope.transport_authority_manifest_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "authenticated recovery classification crossed its sealed bindings"
        )
    consumption_key = (
        os.getpid(),
        exact_root.sha256,
        exact_envelope.operator_nonce_sha256,
    )
    with _CONSUMED_RECOVERY_NONCES_LOCK:
        if consumption_key in _CONSUMED_RECOVERY_NONCES:
            raise TrustedTimeGracefulStopV2Rejected(
                "recovery classification nonce was already consumed"
            )
        _CONSUMED_RECOVERY_NONCES.add(consumption_key)
    return _derive_recovery_intent(
        envelope=exact_envelope,
        root=exact_root,
        classified_transcript=exact_transcript,
        recorded_at_utc=recorded_at_utc,
        capability=capability,
    )


def _mint_fake_authenticated_lifecycle_v2_recovery_intent(
    *,
    envelope: LifecycleV2RecoveryClassificationEnvelope,
    root: LifecycleV2Root,
    classified_transcript: LifecycleV2Transcript,
    recorded_at_utc: str,
    capability: object,
) -> LifecycleV2AuthenticatedRecoveryIntent:
    """Private fake seam; it is capability-separated from production auth."""

    if capability is not _FAKE_RECOVERY_INTENT_CAPABILITY:
        raise TrustedTimeGracefulStopV2Rejected("fake recovery-intent capability is invalid")
    return _derive_recovery_intent(
        envelope=envelope,
        root=root,
        classified_transcript=classified_transcript,
        recorded_at_utc=recorded_at_utc,
        capability=capability,
    )


def require_authenticated_lifecycle_v2_recovery_intent(
    value: object,
) -> LifecycleV2AuthenticatedRecoveryIntent:
    """Require one sealed intent on its originating process and thread."""

    if (
        type(value) is not LifecycleV2AuthenticatedRecoveryIntent
        or value._capability
        not in {
            _PRODUCTION_RECOVERY_INTENT_CAPABILITY,
            _FAKE_RECOVERY_INTENT_CAPABILITY,
        }
        or os.getpid() != value._origin_pid
        or threading.current_thread() is not value._origin_thread
        or type(value.record) is not LifecycleV2ProgressRecord
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "authenticated recovery intent owner or capability is invalid"
        )
    try:
        canonical = decode_lifecycle_v2_progress_record(value.record.encoded)
    except (AttributeError, TrustedTimeGracefulStopV2Rejected) as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "authenticated recovery intent changed under validation"
        ) from error
    evidence = canonical.evidence.to_dict()
    if (
        canonical != value.record
        or canonical.stage
        is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
        or canonical.root_sha256 != value.root_sha256
        or evidence["recovery_classification_envelope_sha256"]
        != value.recovery_classification_envelope_sha256
        or evidence["operator_nonce_sha256"] != value.operator_nonce_sha256
        or evidence["classified_transcript_sha256"]
        != value.classified_transcript_sha256
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "authenticated recovery intent changed under validation"
        )
    return value


def lifecycle_v2_recovery_non_authority_facts() -> dict[str, bool]:
    return {
        "recovery_signer_present": False,
        "recovery_artifact_writer_present": False,
        "transport_dispatch_reachable": False,
        "docker_mutation_reachable": False,
        "effect_continuation_authorized": False,
        "trusted_time_stop_enabled": False,
    }


__all__ = [
    "RECOVERY_CLASSIFICATION_CONTRACT_VERSION",
    "RECOVERY_CLASSIFICATION_MAXIMUM_BYTES",
    "RECOVERY_CLASSIFICATION_REASON_CODES",
    "RECOVERY_CLASSIFICATION_SIGNATURE_DOMAIN",
    "LifecycleV2AuthenticatedRecoveryIntent",
    "LifecycleV2RecoveryClassificationEnvelope",
    "decode_lifecycle_v2_recovery_classification_envelope",
    "lifecycle_v2_recovery_non_authority_facts",
    "require_authenticated_lifecycle_v2_recovery_intent",
]
