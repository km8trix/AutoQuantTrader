"""Pure composition of fresh sequence-1 evidence for a future normal start."""

from __future__ import annotations

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
)
from packages.domain.trusted_time_enrollment_evidence import (
    TrustedTimeFirstEnrollmentIdentities,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentRuntimeReauthentication,
    TrustedTimePostEnrollmentStartApproval,
    require_matching_post_enrollment_runtime_reauthentication,
)


class TrustedTimePostEnrollmentStartCompositionError(ValueError):
    """Fresh runtime evidence cannot satisfy the exact start approval."""


def bind_post_enrollment_start_reauthentication(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    observed: TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
) -> TrustedTimePostEnrollmentRuntimeReauthentication:
    """Reduce one fresh read-only SQL/remote proof to the exact approved binding."""

    if (
        type(approval) is not TrustedTimePostEnrollmentStartApproval
        or type(observed) is not TrustedTimeHeadAnchorFirstEnrollmentPostcondition
    ):
        raise TrustedTimePostEnrollmentStartCompositionError(
            "trusted-time post-enrollment start reauthentication is unavailable"
        )
    try:
        approval.__post_init__()
        observed.__post_init__()
        identities = TrustedTimeFirstEnrollmentIdentities(
            anchor_authority_sha256=observed.anchor_authority_sha256,
            anchor_project_identity_sha256=(observed.anchor_project_identity_sha256),
            bucket_identity_sha256=observed.bucket_identity_sha256,
            deployment_identity_sha256=observed.deployment_identity_sha256,
            host_identity_sha256=observed.host_identity_sha256,
            principal_identity_sha256=observed.principal_identity_sha256,
            runtime_database_identity_sha256=(observed.runtime_database_identity_sha256),
            signing_public_key_sha256=observed.signing_public_key_sha256,
            source_authority_sha256=observed.source_authority_sha256,
        )
        reauthentication = TrustedTimePostEnrollmentRuntimeReauthentication(
            operation_id=approval.operation_id,
            approval_sha256=approval.approval_sha256,
            confirmed_enrollment_evidence_sha256=(approval.confirmed_enrollment.evidence_sha256),
            review_projection_sha256=approval.review.projection_sha256,
            identities=identities,
            anchor_sequence=observed.anchor_sequence,
            checkpoint_reason=observed.checkpoint_reason.value,
            confirmed_anchor_count=observed.confirmed_anchor_count,
            local_highest_anchor_sequence=observed.anchor_sequence,
            remote_highest_anchor_sequence=observed.anchor_sequence,
            remote_object_count=observed.remote_object_count,
            anchor_intent_semantic_sha256=(observed.anchor_intent_semantic_sha256),
            candidate_remote_readback_sha256=(observed.candidate_remote_readback_sha256),
            current_anchor_semantic_sha256=(observed.current_anchor_semantic_sha256),
            current_anchor_sha256=observed.current_anchor_sha256,
            current_host_head_sha256=observed.current_host_head_sha256,
            receipt_semantic_sha256=observed.receipt_semantic_sha256,
            remote_namespace_sha256=observed.remote_namespace_sha256,
            full_audit_completed=observed.full_audit_completed,
            pending_intent_present=observed.pending_intent_present,
            higher_sequence_present=False,
        )
        return require_matching_post_enrollment_runtime_reauthentication(
            approval=approval,
            reauthentication=reauthentication,
        )
    except Exception:
        raise TrustedTimePostEnrollmentStartCompositionError(
            "trusted-time post-enrollment start reauthentication is unavailable"
        ) from None


__all__ = [
    "TrustedTimePostEnrollmentStartCompositionError",
    "bind_post_enrollment_start_reauthentication",
]
