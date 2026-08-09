"""Pure canonical evidence for the Phase 6D trusted-time enrollment bridge.

This module authenticates already-retained, nonsecret first-enrollment evidence.
It owns no filesystem, clock, process, database, provider, control, or trading
authority.  In particular, a valid review projection is not permission to start
the persistent supervisor or to create trusted-time sequence 2.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Never, cast

TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION = "phase6d-one-shot-trusted-time-first-enrollment-v1"
FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION = "phase6d-first-enrollment-exact-operation-approval-v2"
FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION = "phase6d-first-enrollment-single-use-claim-v2"
FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION = "phase6d-first-enrollment-host-outcome-v1"
POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION = "phase6d-post-enrollment-start-evidence-review-v1"

FIRST_ENROLLMENT_HOST_SERVICE = "trusted-time-first-enrollment-host-launcher"
FIRST_ENROLLMENT_RUNTIME_SERVICE = "trusted-time-first-enrollment"
POST_ENROLLMENT_START_REVIEW_SERVICE = "trusted-time-post-enrollment-start-review"

MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES = 16_384

FIRST_ENROLLMENT_AUTHORITY_FIELDS = frozenset(
    {
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    }
)
FIRST_ENROLLMENT_IDENTITY_FIELDS = frozenset(
    {
        "anchor_authority_sha256",
        "anchor_project_identity_sha256",
        "bucket_identity_sha256",
        "deployment_identity_sha256",
        "host_identity_sha256",
        "principal_identity_sha256",
        "runtime_database_identity_sha256",
        "signing_public_key_sha256",
        "source_authority_sha256",
    }
)
FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS = frozenset(
    {
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "current_anchor_semantic_sha256",
        "current_anchor_sha256",
        "current_host_head_sha256",
        "receipt_semantic_sha256",
    }
)
FIRST_ENROLLMENT_APPROVAL_FIELDS = frozenset(
    {
        *FIRST_ENROLLMENT_IDENTITY_FIELDS,
        "approved_git_revision",
        "approved_image_admission_sha256",
        "approved_source_image_id",
        "approved_supervisor_image_id",
        "contract_version",
        "operation_id",
        "operation_mode",
        "prior_new_claim_sha256",
        "prior_new_operation_id",
        "unenrolled_admission_sha256",
    }
)
FIRST_ENROLLMENT_CLAIM_FIELDS = frozenset(
    {
        *FIRST_ENROLLMENT_APPROVAL_FIELDS,
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        "approval_sha256",
        "authority_granted",
        "claim_contract_version",
        "service",
        "status",
    }
)
FIRST_ENROLLMENT_OUTCOME_GATES = frozenset(
    {
        "final_approval_state_validated",
        "final_image_admission_fresh",
        "runtime_inputs_retired",
        "secure_launch_validated",
        "single_use_claim_retained",
        "state_volumes_preserved",
        "terminal_evidence_qualified",
        "topology_removed",
    }
)
FIRST_ENROLLMENT_TERMINAL_FIELDS = frozenset(
    {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *FIRST_ENROLLMENT_IDENTITY_FIELDS,
        *FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS,
        "anchor_sequence",
        "checkpoint_reason",
        "completion_disposition",
        "contract_version",
        "database_secret_disclosed",
        "full_audit_completed",
        "idempotent_duplicate_count",
        "operation_mode",
        "pending_intent_recovered",
        "reason",
        "remote_namespace_sha256",
        "service",
        "status",
        "uploaded_anchor_count",
    }
)
FIRST_ENROLLMENT_OUTCOME_FIELDS = frozenset(
    {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        "approval",
        "approval_sha256",
        "authority_granted",
        "claim_sha256",
        "contract_version",
        "database_secret_disclosed",
        "gates",
        "reason",
        "runtime_terminal",
        "service",
        "status",
    }
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class TrustedTimeFirstEnrollmentOperationMode(StrEnum):
    NEW = "new"
    RECOVER_PENDING = "recover_pending"


class TrustedTimeEnrollmentEvidenceError(ValueError):
    """Retained trusted-time enrollment evidence is malformed or ambiguous."""


class _InvalidEvidence(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidEvidence


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def trusted_time_first_enrollment_identity_sha256(*, kind: str, value: str) -> str:
    """Hash one nonsecret identity with the frozen enrollment domain label."""

    if (
        type(kind) is not str
        or kind not in {"bucket", "host", "principal"}
        or type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedTimeEnrollmentEvidenceError(
            "trusted-time first-enrollment identity binding is invalid"
        )
    digest = hashlib.sha256()
    for item in (
        TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
        "trusted_time_first_enrollment_identity",
        kind,
        value,
    ):
        encoded = item.encode("utf-8", errors="strict")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def canonical_first_enrollment_json_bytes(value: object) -> bytes:
    """Return the exact newline-terminated encoding used by retained evidence."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii", errors="strict")
    except (TypeError, UnicodeError, ValueError):
        raise TrustedTimeEnrollmentEvidenceError(
            "trusted-time first-enrollment evidence is invalid"
        ) from None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _decode_canonical_object(encoded: bytes) -> dict[str, object]:
    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES
    ):
        _invalid()
    try:
        payload = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _invalid(),
        )
    except (
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
        _InvalidEvidence,
    ):
        _invalid()
    if type(payload) is not dict:
        _invalid()
    try:
        canonical = canonical_first_enrollment_json_bytes(payload)
    except TrustedTimeEnrollmentEvidenceError:
        _invalid()
    if canonical != encoded:
        _invalid()
    return cast(dict[str, object], payload)


def _require_exact_keys(payload: object, expected: frozenset[str]) -> dict[str, object]:
    if type(payload) is not dict or set(payload) != expected:
        _invalid()
    return cast(dict[str, object], payload)


def _required_string(payload: Mapping[str, object], field_name: str) -> str:
    value = payload.get(field_name)
    if type(value) is not str:
        _invalid()
    return value


@dataclass(frozen=True, slots=True)
class TrustedTimeImmutableLaunchEvidence:
    """One exact immutable launch tuple, without any execution authority."""

    git_revision: str
    image_admission_sha256: str
    source_image_id: str
    supervisor_image_id: str

    def __post_init__(self) -> None:
        if (
            type(self.git_revision) is not str
            or _GIT_REVISION_PATTERN.fullmatch(self.git_revision) is None
            or not _is_sha256(self.image_admission_sha256)
            or type(self.source_image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.source_image_id) is None
            or type(self.supervisor_image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.supervisor_image_id) is None
            or self.source_image_id == self.supervisor_image_id
        ):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time immutable launch evidence is invalid"
            )

    def payload(self) -> dict[str, str]:
        return {
            "git_revision": self.git_revision,
            "image_admission_sha256": self.image_admission_sha256,
            "source_image_id": self.source_image_id,
            "supervisor_image_id": self.supervisor_image_id,
        }


@dataclass(frozen=True, slots=True)
class TrustedTimeFirstEnrollmentIdentities:
    """Digest-only deployment identities proven by first enrollment."""

    anchor_authority_sha256: str
    anchor_project_identity_sha256: str
    bucket_identity_sha256: str
    deployment_identity_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    runtime_database_identity_sha256: str
    signing_public_key_sha256: str
    source_authority_sha256: str

    def __post_init__(self) -> None:
        if any(not _is_sha256(value) for value in self.payload().values()):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time first-enrollment identities are invalid"
            )

    def payload(self) -> dict[str, str]:
        return {
            field_name: getattr(self, field_name)
            for field_name in sorted(FIRST_ENROLLMENT_IDENTITY_FIELDS)
        }


@dataclass(frozen=True, slots=True)
class TrustedTimeSequenceOneEvidence:
    """Authenticated sequence-1 enrollment result and stable remote namespace."""

    completion_disposition: str
    uploaded_anchor_count: int
    idempotent_duplicate_count: int
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    current_anchor_semantic_sha256: str
    current_anchor_sha256: str
    current_host_head_sha256: str
    receipt_semantic_sha256: str
    remote_namespace_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.completion_disposition) is not str
            or self.completion_disposition != "new_intent_completed"
            or type(self.uploaded_anchor_count) is not int
            or self.uploaded_anchor_count not in {0, 1}
            or type(self.idempotent_duplicate_count) is not int
            or self.idempotent_duplicate_count not in {0, 1}
            or self.uploaded_anchor_count + self.idempotent_duplicate_count != 1
            or any(
                not _is_sha256(value)
                for value in (
                    self.anchor_intent_semantic_sha256,
                    self.candidate_remote_readback_sha256,
                    self.current_anchor_semantic_sha256,
                    self.current_anchor_sha256,
                    self.current_host_head_sha256,
                    self.receipt_semantic_sha256,
                    self.remote_namespace_sha256,
                )
            )
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
        ):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time sequence-1 enrollment evidence is invalid"
            )

    def payload(self) -> dict[str, object]:
        return {
            "anchor_intent_semantic_sha256": self.anchor_intent_semantic_sha256,
            "anchor_sequence": 1,
            "candidate_remote_readback_sha256": self.candidate_remote_readback_sha256,
            "checkpoint_reason": "enrollment",
            "completion_disposition": self.completion_disposition,
            "current_anchor_semantic_sha256": self.current_anchor_semantic_sha256,
            "current_anchor_sha256": self.current_anchor_sha256,
            "current_host_head_sha256": self.current_host_head_sha256,
            "full_audit_completed": True,
            "idempotent_duplicate_count": self.idempotent_duplicate_count,
            "pending_intent_recovered": False,
            "receipt_semantic_sha256": self.receipt_semantic_sha256,
            "remote_namespace_sha256": self.remote_namespace_sha256,
            "uploaded_anchor_count": self.uploaded_anchor_count,
        }


@dataclass(frozen=True, slots=True)
class TrustedTimeConfirmedFirstEnrollment:
    """Exact retained proof that a NEW operation confirmed sequence 1."""

    operation_id: str
    approval_sha256: str
    claim_sha256: str
    outcome_sha256: str
    unenrolled_admission_sha256: str
    enrollment_launch: TrustedTimeImmutableLaunchEvidence
    identities: TrustedTimeFirstEnrollmentIdentities
    sequence_one: TrustedTimeSequenceOneEvidence

    def __post_init__(self) -> None:
        if (
            not _is_uuid4(self.operation_id)
            or any(
                not _is_sha256(value)
                for value in (
                    self.approval_sha256,
                    self.claim_sha256,
                    self.outcome_sha256,
                    self.unenrolled_admission_sha256,
                )
            )
            or type(self.enrollment_launch) is not TrustedTimeImmutableLaunchEvidence
            or type(self.identities) is not TrustedTimeFirstEnrollmentIdentities
            or type(self.sequence_one) is not TrustedTimeSequenceOneEvidence
        ):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time confirmed first-enrollment evidence is invalid"
            )
        self.enrollment_launch.__post_init__()
        self.identities.__post_init__()
        self.sequence_one.__post_init__()

    def payload(self) -> dict[str, object]:
        return {
            "approval_sha256": self.approval_sha256,
            "claim_sha256": self.claim_sha256,
            "enrollment_launch": self.enrollment_launch.payload(),
            "identities": self.identities.payload(),
            "operation_id": self.operation_id,
            "outcome_sha256": self.outcome_sha256,
            "sequence_one": self.sequence_one.payload(),
            "unenrolled_admission_sha256": self.unenrolled_admission_sha256,
        }

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(canonical_first_enrollment_json_bytes(self.payload())).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartReview:
    """Non-authorizing review projection over old proof and a new target tuple."""

    confirmed_enrollment: TrustedTimeConfirmedFirstEnrollment
    proposed_launch: TrustedTimeImmutableLaunchEvidence

    def __post_init__(self) -> None:
        if (
            type(self.confirmed_enrollment) is not TrustedTimeConfirmedFirstEnrollment
            or type(self.proposed_launch) is not TrustedTimeImmutableLaunchEvidence
        ):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time post-enrollment start review is invalid"
            )
        self.confirmed_enrollment.__post_init__()
        self.proposed_launch.__post_init__()
        enrollment_launch = self.confirmed_enrollment.enrollment_launch
        if (
            self.proposed_launch.git_revision == enrollment_launch.git_revision
            or self.proposed_launch.image_admission_sha256
            == enrollment_launch.image_admission_sha256
            or self.proposed_launch.source_image_id == enrollment_launch.source_image_id
            or self.proposed_launch.supervisor_image_id == enrollment_launch.supervisor_image_id
        ):
            raise TrustedTimeEnrollmentEvidenceError(
                "trusted-time post-enrollment start review is invalid"
            )

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        }
        payload.update(
            {
                "authority_granted": False,
                "confirmed_enrollment": self.confirmed_enrollment.payload(),
                "contract_version": POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION,
                "database_secret_disclosed": False,
                "persistent_start_authorized": False,
                "proposed_launch": self.proposed_launch.payload(),
                "sequence_2_authorized": False,
                "service": POST_ENROLLMENT_START_REVIEW_SERVICE,
                "shutdown_authorized": False,
                "status": "review_required",
            }
        )
        return payload

    @property
    def projection_sha256(self) -> str:
        return hashlib.sha256(canonical_first_enrollment_json_bytes(self.payload())).hexdigest()


def _approval_from_claim(
    claim: Mapping[str, object],
    *,
    expected_operation_id: str,
) -> tuple[
    dict[str, object],
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeFirstEnrollmentIdentities,
]:
    approval = {field_name: claim[field_name] for field_name in FIRST_ENROLLMENT_APPROVAL_FIELDS}
    if (
        approval.get("contract_version") != FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION
        or approval.get("operation_id") != expected_operation_id
        or approval.get("operation_mode") != TrustedTimeFirstEnrollmentOperationMode.NEW.value
        or approval.get("prior_new_operation_id") is not None
        or approval.get("prior_new_claim_sha256") is not None
        or not _is_sha256(approval.get("unenrolled_admission_sha256"))
    ):
        _invalid()
    try:
        launch = TrustedTimeImmutableLaunchEvidence(
            git_revision=_required_string(approval, "approved_git_revision"),
            image_admission_sha256=_required_string(approval, "approved_image_admission_sha256"),
            source_image_id=_required_string(approval, "approved_source_image_id"),
            supervisor_image_id=_required_string(approval, "approved_supervisor_image_id"),
        )
        identities = TrustedTimeFirstEnrollmentIdentities(
            **{
                field_name: _required_string(approval, field_name)
                for field_name in FIRST_ENROLLMENT_IDENTITY_FIELDS
            }
        )
    except (TypeError, TrustedTimeEnrollmentEvidenceError):
        _invalid()
    return approval, launch, identities


def _sequence_one_from_terminal(
    terminal: object,
    *,
    identities: TrustedTimeFirstEnrollmentIdentities,
) -> TrustedTimeSequenceOneEvidence:
    value = _require_exact_keys(terminal, FIRST_ENROLLMENT_TERMINAL_FIELDS)
    if (
        any(value.get(field_name) is not False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS)
        or value.get("contract_version") != TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION
        or value.get("database_secret_disclosed") is not False
        or value.get("operation_mode") != TrustedTimeFirstEnrollmentOperationMode.NEW.value
        or value.get("reason") != "first_enrollment_confirmed"
        or value.get("service") != FIRST_ENROLLMENT_RUNTIME_SERVICE
        or value.get("status") != "confirmed"
        or type(value.get("anchor_sequence")) is not int
        or value.get("anchor_sequence") != 1
        or value.get("checkpoint_reason") != "enrollment"
        or value.get("completion_disposition") != "new_intent_completed"
        or value.get("full_audit_completed") is not True
        or value.get("pending_intent_recovered") is not False
        or any(value.get(field_name) != item for field_name, item in identities.payload().items())
        or any(
            not _is_sha256(value.get(field_name))
            for field_name in FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS
        )
        or not _is_sha256(value.get("remote_namespace_sha256"))
    ):
        _invalid()
    try:
        return TrustedTimeSequenceOneEvidence(
            completion_disposition=_required_string(value, "completion_disposition"),
            uploaded_anchor_count=value["uploaded_anchor_count"],  # type: ignore[arg-type]
            idempotent_duplicate_count=value["idempotent_duplicate_count"],  # type: ignore[arg-type]
            anchor_intent_semantic_sha256=_required_string(value, "anchor_intent_semantic_sha256"),
            candidate_remote_readback_sha256=_required_string(
                value, "candidate_remote_readback_sha256"
            ),
            current_anchor_semantic_sha256=_required_string(
                value, "current_anchor_semantic_sha256"
            ),
            current_anchor_sha256=_required_string(value, "current_anchor_sha256"),
            current_host_head_sha256=_required_string(value, "current_host_head_sha256"),
            receipt_semantic_sha256=_required_string(value, "receipt_semantic_sha256"),
            remote_namespace_sha256=_required_string(value, "remote_namespace_sha256"),
        )
    except (TypeError, TrustedTimeEnrollmentEvidenceError):
        _invalid()


def decode_confirmed_first_enrollment(
    *,
    claim_encoded: bytes,
    outcome_encoded: bytes,
    expected_operation_id: str,
    expected_claim_sha256: str,
    expected_outcome_sha256: str,
) -> TrustedTimeConfirmedFirstEnrollment:
    """Authenticate one exact canonical NEW claim and its confirmed host outcome."""

    try:
        if (
            not _is_uuid4(expected_operation_id)
            or not _is_sha256(expected_claim_sha256)
            or not _is_sha256(expected_outcome_sha256)
            or type(claim_encoded) is not bytes
            or hashlib.sha256(claim_encoded).hexdigest() != expected_claim_sha256
            or type(outcome_encoded) is not bytes
            or hashlib.sha256(outcome_encoded).hexdigest() != expected_outcome_sha256
        ):
            _invalid()

        claim = _require_exact_keys(
            _decode_canonical_object(claim_encoded),
            FIRST_ENROLLMENT_CLAIM_FIELDS,
        )
        approval, enrollment_launch, identities = _approval_from_claim(
            claim,
            expected_operation_id=expected_operation_id,
        )
        approval_sha256 = hashlib.sha256(
            canonical_first_enrollment_json_bytes(approval)
        ).hexdigest()
        if (
            claim.get("approval_sha256") != approval_sha256
            or claim.get("authority_granted") is not False
            or claim.get("claim_contract_version") != FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION
            or claim.get("service") != FIRST_ENROLLMENT_HOST_SERVICE
            or claim.get("status") != "claimed"
            or any(
                claim.get(field_name) is not False
                for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
            )
        ):
            _invalid()

        outcome = _require_exact_keys(
            _decode_canonical_object(outcome_encoded),
            FIRST_ENROLLMENT_OUTCOME_FIELDS,
        )
        outcome_approval = _require_exact_keys(
            outcome.get("approval"),
            FIRST_ENROLLMENT_APPROVAL_FIELDS,
        )
        gates = _require_exact_keys(outcome.get("gates"), FIRST_ENROLLMENT_OUTCOME_GATES)
        if (
            outcome_approval != approval
            or outcome.get("approval_sha256") != approval_sha256
            or outcome.get("authority_granted") is not False
            or outcome.get("claim_sha256") != expected_claim_sha256
            or outcome.get("contract_version") != FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION
            or outcome.get("database_secret_disclosed") is not False
            or outcome.get("reason") != "first_enrollment_confirmed"
            or outcome.get("service") != FIRST_ENROLLMENT_HOST_SERVICE
            or outcome.get("status") != "confirmed"
            or any(
                outcome.get(field_name) is not False
                for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
            )
            or any(gates.get(gate_name) is not True for gate_name in FIRST_ENROLLMENT_OUTCOME_GATES)
        ):
            _invalid()
        sequence_one = _sequence_one_from_terminal(
            outcome.get("runtime_terminal"),
            identities=identities,
        )
        return TrustedTimeConfirmedFirstEnrollment(
            operation_id=expected_operation_id,
            approval_sha256=approval_sha256,
            claim_sha256=expected_claim_sha256,
            outcome_sha256=expected_outcome_sha256,
            unenrolled_admission_sha256=_required_string(approval, "unenrolled_admission_sha256"),
            enrollment_launch=enrollment_launch,
            identities=identities,
            sequence_one=sequence_one,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        _InvalidEvidence,
    ):
        raise TrustedTimeEnrollmentEvidenceError(
            "trusted-time confirmed first-enrollment evidence is invalid"
        ) from None


def build_post_enrollment_start_review(
    *,
    confirmed_enrollment: TrustedTimeConfirmedFirstEnrollment,
    proposed_launch: TrustedTimeImmutableLaunchEvidence,
) -> TrustedTimePostEnrollmentStartReview:
    """Bind retained sequence 1 to a distinct proposed launch without authorizing it."""

    return TrustedTimePostEnrollmentStartReview(
        confirmed_enrollment=confirmed_enrollment,
        proposed_launch=proposed_launch,
    )


__all__ = [
    "FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION",
    "FIRST_ENROLLMENT_APPROVAL_FIELDS",
    "FIRST_ENROLLMENT_AUTHORITY_FIELDS",
    "FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION",
    "FIRST_ENROLLMENT_CLAIM_FIELDS",
    "FIRST_ENROLLMENT_HOST_SERVICE",
    "FIRST_ENROLLMENT_IDENTITY_FIELDS",
    "FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION",
    "FIRST_ENROLLMENT_OUTCOME_FIELDS",
    "FIRST_ENROLLMENT_OUTCOME_GATES",
    "FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS",
    "FIRST_ENROLLMENT_RUNTIME_SERVICE",
    "FIRST_ENROLLMENT_TERMINAL_FIELDS",
    "MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES",
    "POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_REVIEW_SERVICE",
    "TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION",
    "TrustedTimeConfirmedFirstEnrollment",
    "TrustedTimeEnrollmentEvidenceError",
    "TrustedTimeFirstEnrollmentIdentities",
    "TrustedTimeFirstEnrollmentOperationMode",
    "TrustedTimeImmutableLaunchEvidence",
    "TrustedTimePostEnrollmentStartReview",
    "TrustedTimeSequenceOneEvidence",
    "build_post_enrollment_start_review",
    "canonical_first_enrollment_json_bytes",
    "decode_confirmed_first_enrollment",
    "trusted_time_first_enrollment_identity_sha256",
]
