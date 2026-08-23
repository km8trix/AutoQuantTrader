"""Pure evidence contracts for a future post-enrollment trusted-time start.

Nothing in this module opens a file, reads a clock, contacts a database or
provider, starts a process, or grants release, shutdown, control, or trading
authority.  It only binds exact nonsecret evidence for later review.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from enum import StrEnum

from packages.domain._trusted_time_post_enrollment_projection_bootstrap import (
    _finalize_post_enrollment_start_domain_projection_types,
    _stage_post_enrollment_runtime_reauthentication_projection_type,
    _stage_post_enrollment_start_approval_projection_type,
    _stage_post_enrollment_start_claim_projection_type,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimePostEnrollmentStartReview,
    canonical_first_enrollment_json_bytes,
)

POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-exact-operation-approval-v1"
)
POST_ENROLLMENT_START_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-runtime-reauthentication-v1"
)
POST_ENROLLMENT_START_CLAIM_CONTRACT_VERSION = "phase6d-post-enrollment-start-single-use-claim-v1"
POST_ENROLLMENT_START_OUTCOME_CONTRACT_VERSION = "phase6d-post-enrollment-start-host-outcome-v1"
POST_ENROLLMENT_START_SERVICE = "trusted-time-post-enrollment-start"
POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE = 1
POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE = 2
POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON = "epoch_rotation"


class TrustedTimePostEnrollmentStartError(ValueError):
    """Post-enrollment start evidence is malformed or conflicts."""


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


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _closed_authority_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update(
        {
            "authority_granted": False,
            "database_secret_disclosed": False,
            "persistent_start_authorized": False,
            "release_authorized": False,
            "sequence_2_authorized": False,
            "shutdown_authorized": False,
        }
    )
    return payload


@_stage_post_enrollment_start_approval_projection_type
@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartApproval:
    """Canonical exact-operation projection requiring separate human approval."""

    operation_id: str
    review: TrustedTimePostEnrollmentStartReview

    def __post_init__(self) -> None:
        if (
            not _is_uuid4(self.operation_id)
            or type(self.review) is not TrustedTimePostEnrollmentStartReview
        ):
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start approval is invalid"
            )
        try:
            self.review.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start approval is invalid"
            ) from None
        if self.operation_id == self.review.confirmed_enrollment.operation_id:
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start approval is invalid"
            )

    @property
    def confirmed_enrollment(self) -> TrustedTimeConfirmedFirstEnrollment:
        return self.review.confirmed_enrollment

    @property
    def proposed_launch(self) -> TrustedTimeImmutableLaunchEvidence:
        return self.review.proposed_launch

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = _closed_authority_payload()
        payload.update(
            {
                "confirmed_enrollment": self.confirmed_enrollment.payload(),
                "confirmed_enrollment_evidence_sha256": (self.confirmed_enrollment.evidence_sha256),
                "contract_version": POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION,
                "expected_predecessor_sequence": (
                    POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE
                ),
                "expected_successor_reason": POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON,
                "expected_successor_sequence": (POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE),
                "operation_id": self.operation_id,
                "proposed_launch": self.proposed_launch.payload(),
                "review_projection_sha256": self.review.projection_sha256,
                "service": POST_ENROLLMENT_START_SERVICE,
                "status": "approval_projection_external_attestation_required",
            }
        )
        return payload

    @property
    def approval_sha256(self) -> str:
        return _sha256_payload(self.payload())


@_stage_post_enrollment_runtime_reauthentication_projection_type
@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentRuntimeReauthentication:
    """Unsealed digest projection; freshness belongs to the runtime issuer."""

    operation_id: str
    approval_sha256: str
    confirmed_enrollment_evidence_sha256: str
    review_projection_sha256: str
    identities: TrustedTimeFirstEnrollmentIdentities
    anchor_sequence: int
    checkpoint_reason: str
    confirmed_anchor_count: int
    local_highest_anchor_sequence: int
    remote_highest_anchor_sequence: int
    remote_object_count: int
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    current_anchor_semantic_sha256: str
    current_anchor_sha256: str
    current_host_head_sha256: str
    receipt_semantic_sha256: str
    remote_namespace_sha256: str
    full_audit_completed: bool
    pending_intent_present: bool
    higher_sequence_present: bool

    def __post_init__(self) -> None:
        result_digests = (
            self.anchor_intent_semantic_sha256,
            self.candidate_remote_readback_sha256,
            self.current_anchor_semantic_sha256,
            self.current_anchor_sha256,
            self.current_host_head_sha256,
            self.receipt_semantic_sha256,
            self.remote_namespace_sha256,
        )
        if (
            not _is_uuid4(self.operation_id)
            or not _is_sha256(self.approval_sha256)
            or not _is_sha256(self.confirmed_enrollment_evidence_sha256)
            or not _is_sha256(self.review_projection_sha256)
            or type(self.identities) is not TrustedTimeFirstEnrollmentIdentities
            or type(self.anchor_sequence) is not int
            or self.anchor_sequence != 1
            or type(self.checkpoint_reason) is not str
            or self.checkpoint_reason != "enrollment"
            or type(self.confirmed_anchor_count) is not int
            or self.confirmed_anchor_count != 1
            or type(self.local_highest_anchor_sequence) is not int
            or self.local_highest_anchor_sequence != 1
            or type(self.remote_highest_anchor_sequence) is not int
            or self.remote_highest_anchor_sequence != 1
            or type(self.remote_object_count) is not int
            or self.remote_object_count != 1
            or any(not _is_sha256(value) for value in result_digests)
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
            or self.full_audit_completed is not True
            or self.pending_intent_present is not False
            or self.higher_sequence_present is not False
        ):
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment runtime reauthentication is invalid"
            )
        try:
            self.identities.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment runtime reauthentication is invalid"
            ) from None

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = _closed_authority_payload()
        payload.update(
            {
                "anchor_intent_semantic_sha256": self.anchor_intent_semantic_sha256,
                "anchor_sequence": self.anchor_sequence,
                "approval_sha256": self.approval_sha256,
                "candidate_remote_readback_sha256": (self.candidate_remote_readback_sha256),
                "checkpoint_reason": self.checkpoint_reason,
                "confirmed_anchor_count": self.confirmed_anchor_count,
                "confirmed_enrollment_evidence_sha256": (self.confirmed_enrollment_evidence_sha256),
                "contract_version": (POST_ENROLLMENT_START_REAUTHENTICATION_CONTRACT_VERSION),
                "current_anchor_semantic_sha256": self.current_anchor_semantic_sha256,
                "current_anchor_sha256": self.current_anchor_sha256,
                "current_host_head_sha256": self.current_host_head_sha256,
                "full_audit_completed": self.full_audit_completed,
                "higher_sequence_present": self.higher_sequence_present,
                "identities": self.identities.payload(),
                "local_highest_anchor_sequence": self.local_highest_anchor_sequence,
                "operation_id": self.operation_id,
                "pending_intent_present": self.pending_intent_present,
                "receipt_semantic_sha256": self.receipt_semantic_sha256,
                "remote_highest_anchor_sequence": self.remote_highest_anchor_sequence,
                "remote_namespace_sha256": self.remote_namespace_sha256,
                "remote_object_count": self.remote_object_count,
                "review_projection_sha256": self.review_projection_sha256,
                "service": POST_ENROLLMENT_START_SERVICE,
                "status": "runtime_reauthentication_projection_unsealed",
            }
        )
        return payload

    @property
    def evidence_sha256(self) -> str:
        return _sha256_payload(self.payload())


def require_matching_post_enrollment_runtime_reauthentication(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    reauthentication: TrustedTimePostEnrollmentRuntimeReauthentication,
) -> TrustedTimePostEnrollmentRuntimeReauthentication:
    """Require one unsealed observation projection to equal the approved sequence 1."""

    if (
        type(approval) is not TrustedTimePostEnrollmentStartApproval
        or type(reauthentication) is not TrustedTimePostEnrollmentRuntimeReauthentication
    ):
        raise TrustedTimePostEnrollmentStartError(
            "trusted-time post-enrollment runtime reauthentication differs from approval"
        )
    try:
        approval.__post_init__()
        reauthentication.__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentStartError(
            "trusted-time post-enrollment runtime reauthentication differs from approval"
        ) from None
    confirmed = approval.confirmed_enrollment
    sequence_one = confirmed.sequence_one
    if (
        reauthentication.operation_id != approval.operation_id
        or reauthentication.approval_sha256 != approval.approval_sha256
        or reauthentication.confirmed_enrollment_evidence_sha256 != confirmed.evidence_sha256
        or reauthentication.review_projection_sha256 != approval.review.projection_sha256
        or reauthentication.identities != confirmed.identities
        or reauthentication.anchor_intent_semantic_sha256
        != sequence_one.anchor_intent_semantic_sha256
        or reauthentication.candidate_remote_readback_sha256
        != sequence_one.candidate_remote_readback_sha256
        or reauthentication.current_anchor_semantic_sha256
        != sequence_one.current_anchor_semantic_sha256
        or reauthentication.current_anchor_sha256 != sequence_one.current_anchor_sha256
        or reauthentication.current_host_head_sha256 != sequence_one.current_host_head_sha256
        or reauthentication.receipt_semantic_sha256 != sequence_one.receipt_semantic_sha256
        or reauthentication.remote_namespace_sha256 != sequence_one.remote_namespace_sha256
    ):
        raise TrustedTimePostEnrollmentStartError(
            "trusted-time post-enrollment runtime reauthentication differs from approval"
        )
    return reauthentication


@_stage_post_enrollment_start_claim_projection_type
@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartClaim:
    """Non-authorizing single-use claim projection immediately before release."""

    approval: TrustedTimePostEnrollmentStartApproval
    reauthentication: TrustedTimePostEnrollmentRuntimeReauthentication

    def __post_init__(self) -> None:
        try:
            require_matching_post_enrollment_runtime_reauthentication(
                approval=self.approval,
                reauthentication=self.reauthentication,
            )
        except Exception:
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start claim is invalid"
            ) from None

    @property
    def operation_id(self) -> str:
        return self.approval.operation_id

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = _closed_authority_payload()
        payload.update(
            {
                "approval": self.approval.payload(),
                "approval_sha256": self.approval.approval_sha256,
                "claim_contract_version": POST_ENROLLMENT_START_CLAIM_CONTRACT_VERSION,
                "operation_id": self.operation_id,
                "reauthentication": self.reauthentication.payload(),
                "reauthentication_sha256": self.reauthentication.evidence_sha256,
                "service": POST_ENROLLMENT_START_SERVICE,
                "status": "claim_projection_not_retained",
            }
        )
        return payload

    @property
    def claim_sha256(self) -> str:
        return _sha256_payload(self.payload())


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartSuccessor:
    """Unqualified sequence-2 candidate; never authenticated topology proof."""

    anchor_sequence: int
    checkpoint_reason: str
    predecessor_anchor_sha256: str
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    current_anchor_semantic_sha256: str
    current_anchor_sha256: str
    current_host_head_sha256: str
    receipt_semantic_sha256: str
    remote_namespace_sha256: str
    confirmed_anchor_count: int
    remote_object_count: int
    local_highest_anchor_sequence: int
    remote_highest_anchor_sequence: int
    full_audit_completed: bool
    pending_intent_present: bool
    higher_sequence_present: bool

    def __post_init__(self) -> None:
        digests = (
            self.predecessor_anchor_sha256,
            self.anchor_intent_semantic_sha256,
            self.candidate_remote_readback_sha256,
            self.current_anchor_semantic_sha256,
            self.current_anchor_sha256,
            self.current_host_head_sha256,
            self.receipt_semantic_sha256,
            self.remote_namespace_sha256,
        )
        if (
            type(self.anchor_sequence) is not int
            or self.anchor_sequence != POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE
            or type(self.checkpoint_reason) is not str
            or self.checkpoint_reason != POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON
            or any(not _is_sha256(value) for value in digests)
            or self.current_anchor_sha256 == self.predecessor_anchor_sha256
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
            or type(self.confirmed_anchor_count) is not int
            or self.confirmed_anchor_count != 2
            or type(self.remote_object_count) is not int
            or self.remote_object_count != 2
            or type(self.local_highest_anchor_sequence) is not int
            or self.local_highest_anchor_sequence != 2
            or type(self.remote_highest_anchor_sequence) is not int
            or self.remote_highest_anchor_sequence != 2
            or self.full_audit_completed is not True
            or self.pending_intent_present is not False
            or self.higher_sequence_present is not False
        ):
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start successor is invalid"
            )

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = _closed_authority_payload()
        payload.update(
            {
                "anchor_intent_semantic_sha256": self.anchor_intent_semantic_sha256,
                "anchor_sequence": self.anchor_sequence,
                "candidate_remote_readback_sha256": (self.candidate_remote_readback_sha256),
                "checkpoint_reason": self.checkpoint_reason,
                "confirmed_anchor_count": self.confirmed_anchor_count,
                "current_anchor_semantic_sha256": self.current_anchor_semantic_sha256,
                "current_anchor_sha256": self.current_anchor_sha256,
                "current_host_head_sha256": self.current_host_head_sha256,
                "full_audit_completed": self.full_audit_completed,
                "higher_sequence_present": self.higher_sequence_present,
                "local_highest_anchor_sequence": self.local_highest_anchor_sequence,
                "pending_intent_present": self.pending_intent_present,
                "predecessor_anchor_sha256": self.predecessor_anchor_sha256,
                "receipt_semantic_sha256": self.receipt_semantic_sha256,
                "remote_highest_anchor_sequence": self.remote_highest_anchor_sequence,
                "remote_namespace_sha256": self.remote_namespace_sha256,
                "remote_object_count": self.remote_object_count,
                "status": "successor_candidate_unqualified",
            }
        )
        return payload


class TrustedTimePostEnrollmentStartOutcomeStatus(StrEnum):
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartOutcome:
    """Unconfirmed host-outcome projection; no runtime proof issuer exists yet."""

    claim: TrustedTimePostEnrollmentStartClaim
    successor: TrustedTimePostEnrollmentStartSuccessor | None

    def __post_init__(self) -> None:
        if type(self.claim) is not TrustedTimePostEnrollmentStartClaim or (
            self.successor is not None
            and type(self.successor) is not TrustedTimePostEnrollmentStartSuccessor
        ):
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start outcome is invalid"
            )
        try:
            self.claim.__post_init__()
            if self.successor is not None:
                self.successor.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start outcome is invalid"
            ) from None
        if (
            self.successor is not None
            and self.successor.predecessor_anchor_sha256
            != self.claim.reauthentication.current_anchor_sha256
        ):
            raise TrustedTimePostEnrollmentStartError(
                "trusted-time post-enrollment start outcome is invalid"
            )

    @property
    def qualified(self) -> bool:
        return False

    @property
    def status(self) -> TrustedTimePostEnrollmentStartOutcomeStatus:
        return TrustedTimePostEnrollmentStartOutcomeStatus.UNCONFIRMED

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = _closed_authority_payload()
        payload.update(
            {
                "claim_sha256": self.claim.claim_sha256,
                "contract_version": POST_ENROLLMENT_START_OUTCOME_CONTRACT_VERSION,
                "operation_id": self.claim.operation_id,
                "persistent_start_confirmed": False,
                "qualified": False,
                "reason": "post_enrollment_start_recovery_required",
                "sequence_2_confirmed": False,
                "service": POST_ENROLLMENT_START_SERVICE,
                "status": self.status.value,
                "successor_candidate": (
                    None if self.successor is None else self.successor.payload()
                ),
                "topology_qualified": False,
            }
        )
        return payload

    @property
    def outcome_sha256(self) -> str:
        return _sha256_payload(self.payload())


_finalize_post_enrollment_start_domain_projection_types()
del _finalize_post_enrollment_start_domain_projection_types
del _stage_post_enrollment_runtime_reauthentication_projection_type
del _stage_post_enrollment_start_approval_projection_type
del _stage_post_enrollment_start_claim_projection_type


__all__ = [
    "POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_CLAIM_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE",
    "POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON",
    "POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE",
    "POST_ENROLLMENT_START_OUTCOME_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_REAUTHENTICATION_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_SERVICE",
    "TrustedTimePostEnrollmentRuntimeReauthentication",
    "TrustedTimePostEnrollmentStartApproval",
    "TrustedTimePostEnrollmentStartClaim",
    "TrustedTimePostEnrollmentStartError",
    "TrustedTimePostEnrollmentStartOutcome",
    "TrustedTimePostEnrollmentStartOutcomeStatus",
    "TrustedTimePostEnrollmentStartSuccessor",
    "require_matching_post_enrollment_runtime_reauthentication",
]
