"""Canonical classification-only recovery evidence for lifecycle v2.

This module defines signed, non-effecting recovery-classification bytes.  It
does not load a key, authenticate a signature, publish an artifact, resume an
effect, or grant graceful-stop authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Self, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_MAXIMUM_ENTRIES,
    LIFECYCLE_V2_OPERATION_BUDGET_NS,
    LIFECYCLE_V2_SERVICE,
    MAXIMUM_SIGNED_INTEGER,
    NORMAL_STAGE_BY_ORDINAL,
    FrozenJsonObject,
    LifecycleV2Stage,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
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
        if fields["reason_code"] not in RECOVERY_CLASSIFICATION_REASON_CODES:
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
    "LifecycleV2RecoveryClassificationEnvelope",
    "decode_lifecycle_v2_recovery_classification_envelope",
    "lifecycle_v2_recovery_non_authority_facts",
]
