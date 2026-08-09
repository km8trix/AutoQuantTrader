from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
)
from apps.trusted_time_supervisor.post_enrollment_start import (
    TrustedTimePostEnrollmentStartCompositionError,
    bind_post_enrollment_start_reauthentication,
)
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeEnrollmentEvidenceError,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
    trusted_time_first_enrollment_identity_sha256,
)
from packages.domain.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION,
    POST_ENROLLMENT_START_CLAIM_CONTRACT_VERSION,
    POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON,
    POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE,
    POST_ENROLLMENT_START_OUTCOME_CONTRACT_VERSION,
    POST_ENROLLMENT_START_REAUTHENTICATION_CONTRACT_VERSION,
    TrustedTimePostEnrollmentRuntimeReauthentication,
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimePostEnrollmentStartClaim,
    TrustedTimePostEnrollmentStartError,
    TrustedTimePostEnrollmentStartOutcome,
    TrustedTimePostEnrollmentStartOutcomeStatus,
    TrustedTimePostEnrollmentStartSuccessor,
    require_matching_post_enrollment_runtime_reauthentication,
)

OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"


def _golden_keys(encoded: str) -> frozenset[str]:
    return frozenset(encoded.split())


_GOLDEN_TOP_LEVEL_KEYS = {
    "approval": _golden_keys(
        """alert_delivery_authorized arming_authorized authority_granted
        automatic_rearm_authorized automatic_resume_authorized broker_action_authorized
        confirmed_enrollment confirmed_enrollment_evidence_sha256 contract_version
        database_secret_disclosed expected_predecessor_sequence expected_successor_reason
        expected_successor_sequence exposure_authorized live_trading_authorized
        new_exposure_authorized operation_id operational_control_authorized
        paper_trading_authorized persistent_start_authorized proposed_launch
        readiness_authorized rearm_authorized release_authorized
        review_projection_sha256 sequence_2_authorized service shutdown_authorized
        status"""
    ),
    "reauthentication": _golden_keys(
        """alert_delivery_authorized anchor_intent_semantic_sha256 anchor_sequence
        approval_sha256 arming_authorized authority_granted automatic_rearm_authorized
        automatic_resume_authorized broker_action_authorized
        candidate_remote_readback_sha256 checkpoint_reason confirmed_anchor_count
        confirmed_enrollment_evidence_sha256 contract_version
        current_anchor_semantic_sha256 current_anchor_sha256 current_host_head_sha256
        database_secret_disclosed exposure_authorized full_audit_completed
        higher_sequence_present identities live_trading_authorized
        local_highest_anchor_sequence new_exposure_authorized operation_id
        operational_control_authorized paper_trading_authorized pending_intent_present
        persistent_start_authorized readiness_authorized rearm_authorized
        receipt_semantic_sha256 release_authorized remote_highest_anchor_sequence
        remote_namespace_sha256 remote_object_count review_projection_sha256
        sequence_2_authorized service shutdown_authorized status"""
    ),
    "claim": _golden_keys(
        """alert_delivery_authorized approval approval_sha256 arming_authorized
        authority_granted automatic_rearm_authorized automatic_resume_authorized
        broker_action_authorized claim_contract_version database_secret_disclosed
        exposure_authorized live_trading_authorized new_exposure_authorized operation_id
        operational_control_authorized paper_trading_authorized persistent_start_authorized
        readiness_authorized rearm_authorized reauthentication reauthentication_sha256
        release_authorized sequence_2_authorized service shutdown_authorized status"""
    ),
    "successor": _golden_keys(
        """alert_delivery_authorized anchor_intent_semantic_sha256 anchor_sequence
        arming_authorized authority_granted automatic_rearm_authorized
        automatic_resume_authorized broker_action_authorized
        candidate_remote_readback_sha256 checkpoint_reason confirmed_anchor_count
        current_anchor_semantic_sha256 current_anchor_sha256 current_host_head_sha256
        database_secret_disclosed exposure_authorized full_audit_completed
        higher_sequence_present live_trading_authorized local_highest_anchor_sequence
        new_exposure_authorized operational_control_authorized paper_trading_authorized
        pending_intent_present persistent_start_authorized predecessor_anchor_sha256
        readiness_authorized rearm_authorized receipt_semantic_sha256 release_authorized
        remote_highest_anchor_sequence remote_namespace_sha256 remote_object_count
        sequence_2_authorized shutdown_authorized status"""
    ),
    "outcome": _golden_keys(
        """alert_delivery_authorized arming_authorized authority_granted
        automatic_rearm_authorized automatic_resume_authorized broker_action_authorized
        claim_sha256 contract_version database_secret_disclosed exposure_authorized
        live_trading_authorized new_exposure_authorized operation_id
        operational_control_authorized paper_trading_authorized persistent_start_authorized
        persistent_start_confirmed qualified readiness_authorized rearm_authorized reason
        release_authorized sequence_2_authorized sequence_2_confirmed service
        shutdown_authorized status successor_candidate topology_qualified"""
    ),
}


def _identities() -> TrustedTimeFirstEnrollmentIdentities:
    return TrustedTimeFirstEnrollmentIdentities(
        anchor_authority_sha256="1" * 64,
        anchor_project_identity_sha256="2" * 64,
        bucket_identity_sha256="3" * 64,
        deployment_identity_sha256="4" * 64,
        host_identity_sha256="5" * 64,
        principal_identity_sha256="6" * 64,
        runtime_database_identity_sha256="7" * 64,
        signing_public_key_sha256="8" * 64,
        source_authority_sha256="9" * 64,
    )


def _sequence_one() -> TrustedTimeSequenceOneEvidence:
    return TrustedTimeSequenceOneEvidence(
        completion_disposition="new_intent_completed",
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        anchor_intent_semantic_sha256="a" * 64,
        candidate_remote_readback_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        current_anchor_sha256="b" * 64,
        current_host_head_sha256="d" * 64,
        receipt_semantic_sha256="e" * 64,
        remote_namespace_sha256="f" * 64,
    )


def _confirmed() -> TrustedTimeConfirmedFirstEnrollment:
    return TrustedTimeConfirmedFirstEnrollment(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="0" * 64,
        claim_sha256="1" * 64,
        outcome_sha256="2" * 64,
        unenrolled_admission_sha256="3" * 64,
        enrollment_launch=TrustedTimeImmutableLaunchEvidence(
            git_revision="a" * 40,
            image_admission_sha256="4" * 64,
            source_image_id="sha256:" + "5" * 64,
            supervisor_image_id="sha256:" + "6" * 64,
        ),
        identities=_identities(),
        sequence_one=_sequence_one(),
    )


def _approval() -> TrustedTimePostEnrollmentStartApproval:
    review = build_post_enrollment_start_review(
        confirmed_enrollment=_confirmed(),
        proposed_launch=TrustedTimeImmutableLaunchEvidence(
            git_revision="f" * 40,
            image_admission_sha256="7" * 64,
            source_image_id="sha256:" + "8" * 64,
            supervisor_image_id="sha256:" + "9" * 64,
        ),
    )
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=OPERATION_ID,
        review=review,
    )


def _reauthentication() -> TrustedTimePostEnrollmentRuntimeReauthentication:
    approval = _approval()
    confirmed = approval.confirmed_enrollment
    sequence = confirmed.sequence_one
    return TrustedTimePostEnrollmentRuntimeReauthentication(
        operation_id=approval.operation_id,
        approval_sha256=approval.approval_sha256,
        confirmed_enrollment_evidence_sha256=confirmed.evidence_sha256,
        review_projection_sha256=approval.review.projection_sha256,
        identities=confirmed.identities,
        anchor_sequence=1,
        checkpoint_reason="enrollment",
        confirmed_anchor_count=1,
        local_highest_anchor_sequence=1,
        remote_highest_anchor_sequence=1,
        remote_object_count=1,
        anchor_intent_semantic_sha256=sequence.anchor_intent_semantic_sha256,
        candidate_remote_readback_sha256=sequence.candidate_remote_readback_sha256,
        current_anchor_semantic_sha256=sequence.current_anchor_semantic_sha256,
        current_anchor_sha256=sequence.current_anchor_sha256,
        current_host_head_sha256=sequence.current_host_head_sha256,
        receipt_semantic_sha256=sequence.receipt_semantic_sha256,
        remote_namespace_sha256=sequence.remote_namespace_sha256,
        full_audit_completed=True,
        pending_intent_present=False,
        higher_sequence_present=False,
    )


def _observed_postcondition() -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
    identities = _identities()
    sequence = _sequence_one()
    return TrustedTimeHeadAnchorFirstEnrollmentPostcondition(
        anchor_sequence=1,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        confirmed_anchor_count=1,
        local_transition_count=2,
        confirmed_anchor_local_transition_ordinal=2,
        remote_object_count=1,
        current_host_head_sha256=sequence.current_host_head_sha256,
        current_anchor_sha256=sequence.current_anchor_sha256,
        current_anchor_semantic_sha256=sequence.current_anchor_semantic_sha256,
        anchor_intent_semantic_sha256=sequence.anchor_intent_semantic_sha256,
        candidate_remote_readback_sha256=sequence.candidate_remote_readback_sha256,
        receipt_semantic_sha256=sequence.receipt_semantic_sha256,
        remote_namespace_sha256=sequence.remote_namespace_sha256,
        anchor_authority_sha256=identities.anchor_authority_sha256,
        deployment_identity_sha256=identities.deployment_identity_sha256,
        runtime_database_identity_sha256=identities.runtime_database_identity_sha256,
        anchor_project_identity_sha256=identities.anchor_project_identity_sha256,
        source_authority_sha256=identities.source_authority_sha256,
        signing_public_key_sha256=identities.signing_public_key_sha256,
        host_identity_sha256=identities.host_identity_sha256,
        principal_identity_sha256=identities.principal_identity_sha256,
        bucket_identity_sha256=identities.bucket_identity_sha256,
        full_audit_completed=True,
        pending_intent_present=False,
    )


def _claim() -> TrustedTimePostEnrollmentStartClaim:
    return TrustedTimePostEnrollmentStartClaim(
        approval=_approval(),
        reauthentication=_reauthentication(),
    )


def _successor() -> TrustedTimePostEnrollmentStartSuccessor:
    return TrustedTimePostEnrollmentStartSuccessor(
        anchor_sequence=2,
        checkpoint_reason="epoch_rotation",
        predecessor_anchor_sha256="b" * 64,
        anchor_intent_semantic_sha256="0" * 64,
        candidate_remote_readback_sha256="1" * 64,
        current_anchor_semantic_sha256="2" * 64,
        current_anchor_sha256="1" * 64,
        current_host_head_sha256="3" * 64,
        receipt_semantic_sha256="4" * 64,
        remote_namespace_sha256="5" * 64,
        confirmed_anchor_count=2,
        remote_object_count=2,
        local_highest_anchor_sequence=2,
        remote_highest_anchor_sequence=2,
        full_audit_completed=True,
        pending_intent_present=False,
        higher_sequence_present=False,
    )


def test_literal_v1_contracts_keys_and_wire_hashes_are_frozen() -> None:
    approval = _approval()
    reauthentication = _reauthentication()
    claim = _claim()
    successor = _successor()
    outcome = TrustedTimePostEnrollmentStartOutcome(
        claim=claim,
        successor=successor,
    )
    values = {
        "approval": approval,
        "reauthentication": reauthentication,
        "claim": claim,
        "successor": successor,
        "outcome": outcome,
    }

    assert POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION == (
        "phase6d-post-enrollment-start-exact-operation-approval-v1"
    )
    assert POST_ENROLLMENT_START_REAUTHENTICATION_CONTRACT_VERSION == (
        "phase6d-post-enrollment-start-runtime-reauthentication-v1"
    )
    assert POST_ENROLLMENT_START_CLAIM_CONTRACT_VERSION == (
        "phase6d-post-enrollment-start-single-use-claim-v1"
    )
    assert POST_ENROLLMENT_START_OUTCOME_CONTRACT_VERSION == (
        "phase6d-post-enrollment-start-host-outcome-v1"
    )
    assert {name: set(value.payload()) for name, value in values.items()} == {
        name: set(keys) for name, keys in _GOLDEN_TOP_LEVEL_KEYS.items()
    }
    assert approval.approval_sha256 == (
        "4c16b80407951b4d3661fb95daab656a549283aa000b255ebfb847c49d6eee0e"
    )
    assert reauthentication.evidence_sha256 == (
        "769d5570e0dcb7bfb4fa5c736bcb77e4e2aeae0c9df257dad154017c20b352a9"
    )
    assert claim.claim_sha256 == (
        "a5b84d654d251e7da6daa407bb06cfcd9eaabb8ad8457d0d522cfb9ab613f6eb"
    )
    assert (
        hashlib.sha256(canonical_first_enrollment_json_bytes(successor.payload())).hexdigest()
        == "91e931cc68e1f143f23f5be93671daee69652bfb8c7a4be4ecddb7d3c87a3edd"
    )
    assert successor.payload()["status"] == "successor_candidate_unqualified"
    assert outcome.outcome_sha256 == (
        "f9e84ff9820ca635334b828eab074b5587fa08d2934518fa69ad1d115cedf14b"
    )


def test_identity_digest_is_frozen_domain_separated_and_strict() -> None:
    host = trusted_time_first_enrollment_identity_sha256(kind="host", value="same")
    principal = trusted_time_first_enrollment_identity_sha256(
        kind="principal",
        value="same",
    )

    assert host == "2b45a447d718f78269713f35c2e2ef102a60243fbb2299386b6cf176187b25d0"
    assert principal != host
    for kind, value in (("other", "same"), ("host", ""), ("host", " same")):
        with pytest.raises(TrustedTimeEnrollmentEvidenceError):
            trusted_time_first_enrollment_identity_sha256(kind=kind, value=value)


def test_approval_binds_exact_old_evidence_new_tuple_and_fixed_successor_closed() -> None:
    approval = _approval()
    payload = approval.payload()

    assert payload["contract_version"] == POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION
    assert payload["confirmed_enrollment_evidence_sha256"] == (
        approval.confirmed_enrollment.evidence_sha256
    )
    assert payload["review_projection_sha256"] == approval.review.projection_sha256
    assert payload["expected_successor_sequence"] == (
        POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE
    )
    assert payload["expected_successor_reason"] == (POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON)
    assert payload["confirmed_enrollment"]["enrollment_launch"] != payload["proposed_launch"]  # type: ignore[index]
    assert all(payload[field_name] is False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    assert payload["persistent_start_authorized"] is False
    assert payload["release_authorized"] is False
    assert payload["sequence_2_authorized"] is False
    assert payload["status"] == "approval_projection_external_attestation_required"
    assert len(approval.approval_sha256) == 64
    canonical_first_enrollment_json_bytes(payload)

    with pytest.raises(TrustedTimePostEnrollmentStartError):
        TrustedTimePostEnrollmentStartApproval(
            operation_id=approval.confirmed_enrollment.operation_id,
            review=approval.review,
        )


def test_runtime_reauthentication_matches_every_confirmed_sequence_one_binding() -> None:
    approval = _approval()
    reauthentication = _reauthentication()

    assert (
        require_matching_post_enrollment_runtime_reauthentication(
            approval=approval,
            reauthentication=reauthentication,
        )
        is reauthentication
    )
    assert len(reauthentication.evidence_sha256) == 64
    assert reauthentication.payload()["persistent_start_authorized"] is False
    assert reauthentication.payload()["status"] == ("runtime_reauthentication_projection_unsealed")


def test_fresh_attempt_postcondition_composes_to_exact_domain_reauthentication() -> None:
    evidence = bind_post_enrollment_start_reauthentication(
        approval=_approval(),
        observed=_observed_postcondition(),
    )

    assert evidence.payload() == _reauthentication().payload()
    assert evidence.payload()["release_authorized"] is False


def test_fresh_attempt_postcondition_rejects_any_historical_identity_drift() -> None:
    observed = replace(
        _observed_postcondition(),
        principal_identity_sha256="0" * 64,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentStartCompositionError,
        match="reauthentication is unavailable",
    ):
        bind_post_enrollment_start_reauthentication(
            approval=_approval(),
            observed=observed,
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("operation_id", "323e4567-e89b-42d3-a456-426614174002"),
        ("approval_sha256", "0" * 64),
        ("confirmed_enrollment_evidence_sha256", "0" * 64),
        ("review_projection_sha256", "0" * 64),
        ("anchor_intent_semantic_sha256", "0" * 64),
        ("current_anchor_semantic_sha256", "0" * 64),
        ("current_host_head_sha256", "0" * 64),
        ("receipt_semantic_sha256", "0" * 64),
        ("remote_namespace_sha256", "0" * 64),
    ],
)
def test_runtime_reauthentication_comparator_rejects_every_binding_drift(
    field_name: str,
    value: object,
) -> None:
    observed = replace(_reauthentication(), **{field_name: value})

    with pytest.raises(
        TrustedTimePostEnrollmentStartError,
        match="differs from approval",
    ):
        require_matching_post_enrollment_runtime_reauthentication(
            approval=_approval(),
            reauthentication=observed,
        )


def test_runtime_reauthentication_comparator_rejects_matching_readback_anchor_drift() -> None:
    observed = replace(
        _reauthentication(),
        candidate_remote_readback_sha256="0" * 64,
        current_anchor_sha256="0" * 64,
    )

    with pytest.raises(TrustedTimePostEnrollmentStartError, match="differs from approval"):
        require_matching_post_enrollment_runtime_reauthentication(
            approval=_approval(),
            reauthentication=observed,
        )


def test_runtime_reauthentication_rejects_identity_drift() -> None:
    changed_identities = replace(_identities(), host_identity_sha256="0" * 64)
    observed = replace(_reauthentication(), identities=changed_identities)

    with pytest.raises(TrustedTimePostEnrollmentStartError):
        require_matching_post_enrollment_runtime_reauthentication(
            approval=_approval(),
            reauthentication=observed,
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("anchor_sequence", True),
        ("checkpoint_reason", "periodic"),
        ("confirmed_anchor_count", True),
        ("local_highest_anchor_sequence", 2),
        ("remote_highest_anchor_sequence", 2),
        ("remote_object_count", True),
        ("full_audit_completed", 1),
        ("pending_intent_present", 0),
        ("higher_sequence_present", 0),
    ],
)
def test_runtime_reauthentication_rejects_nonexact_state(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentStartError):
        replace(_reauthentication(), **{field_name: value})


def test_claim_binds_matching_approval_and_reauthentication_but_grants_nothing() -> None:
    claim = _claim()
    payload = claim.payload()

    assert payload["approval_sha256"] == claim.approval.approval_sha256
    assert payload["reauthentication_sha256"] == claim.reauthentication.evidence_sha256
    assert payload["status"] == "claim_projection_not_retained"
    assert all(payload[field_name] is False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    assert payload["persistent_start_authorized"] is False
    assert payload["release_authorized"] is False
    assert payload["sequence_2_authorized"] is False
    assert payload["shutdown_authorized"] is False
    assert len(claim.claim_sha256) == 64

    with pytest.raises(FrozenInstanceError):
        claim.approval = _approval()  # type: ignore[misc]


def test_claim_rejects_reauthentication_from_another_operation() -> None:
    approval = _approval()
    other = replace(
        _reauthentication(),
        operation_id="323e4567-e89b-42d3-a456-426614174002",
    )

    with pytest.raises(TrustedTimePostEnrollmentStartError, match="claim is invalid"):
        TrustedTimePostEnrollmentStartClaim(
            approval=approval,
            reauthentication=other,
        )


def test_outcome_cannot_confirm_from_public_successor_candidate() -> None:
    unconfirmed = TrustedTimePostEnrollmentStartOutcome(
        claim=_claim(),
        successor=None,
    )
    candidate = TrustedTimePostEnrollmentStartOutcome(
        claim=_claim(),
        successor=_successor(),
    )

    assert unconfirmed.status is TrustedTimePostEnrollmentStartOutcomeStatus.UNCONFIRMED
    assert unconfirmed.qualified is False
    assert unconfirmed.payload()["persistent_start_confirmed"] is False
    assert candidate.status is TrustedTimePostEnrollmentStartOutcomeStatus.UNCONFIRMED
    assert candidate.qualified is False
    assert candidate.payload()["sequence_2_confirmed"] is False
    assert candidate.payload()["topology_qualified"] is False
    assert candidate.payload()["persistent_start_authorized"] is False
    assert all(
        candidate.payload()[field_name] is False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    )
    assert all(
        _successor().payload()[field_name] is False
        for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    )
    assert _successor().payload()["status"] == "successor_candidate_unqualified"
    assert len(candidate.outcome_sha256) == 64


def test_outcome_rejects_wrong_predecessor_and_boolean_sequence() -> None:
    with pytest.raises(TrustedTimePostEnrollmentStartError):
        TrustedTimePostEnrollmentStartOutcome(
            claim=_claim(),
            successor=replace(_successor(), predecessor_anchor_sha256="0" * 64),
        )
    with pytest.raises(TrustedTimePostEnrollmentStartError):
        replace(_successor(), anchor_sequence=True)
