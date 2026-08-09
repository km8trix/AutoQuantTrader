from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
)
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.domain.trusted_time_enrollment_evidence import (
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentRuntimeReauthentication,
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimePostEnrollmentStartClaim,
)
from scripts import trusted_time_post_enrollment_staging as staging
from scripts.trusted_time_post_enrollment_staging import (
    POST_ENROLLMENT_START_CONTAINER_USER,
    POST_ENROLLMENT_START_RELEASE_COMMAND,
    TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
    TrustedTimePostEnrollmentStartStagingHandoff,
    TrustedTimePostEnrollmentStartStagingRejected,
    post_enrollment_start_release_argv,
    prepare_post_enrollment_start_release_under_lock,
)
from scripts.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_CLAIM_FILE_NAME,
    TrustedTimePostEnrollmentStartClaimConsumed,
    TrustedTimePostEnrollmentStartClaimPersistenceError,
    TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed,
    retain_post_enrollment_start_claim,
)

OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"
OTHER_OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"
SUPERVISOR_CONTAINER_ID = "a" * 64


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


def _approval(
    operation_id: str = OPERATION_ID,
) -> TrustedTimePostEnrollmentStartApproval:
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=operation_id,
        review=build_post_enrollment_start_review(
            confirmed_enrollment=_confirmed(),
            proposed_launch=TrustedTimeImmutableLaunchEvidence(
                git_revision="f" * 40,
                image_admission_sha256="7" * 64,
                source_image_id="sha256:" + "8" * 64,
                supervisor_image_id="sha256:" + "9" * 64,
            ),
        ),
    )


def _reauthentication(
    approval: TrustedTimePostEnrollmentStartApproval,
) -> TrustedTimePostEnrollmentRuntimeReauthentication:
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


def _claim(
    operation_id: str = OPERATION_ID,
) -> TrustedTimePostEnrollmentStartClaim:
    approval = _approval(operation_id)
    return TrustedTimePostEnrollmentStartClaim(
        approval=approval,
        reauthentication=_reauthentication(approval),
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


def _artifact_paths(tmp_path: Path) -> tuple[Path, Path]:
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    return ignored_root, artifact_directory


class _Issuer:
    def __init__(
        self,
        observed: TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
        events: list[str] | None = None,
        *,
        error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.observed = observed
        self.events = events if events is not None else []
        self.error = error
        self.close_error = close_error
        self.reauthentication_calls = 0
        self.close_calls = 0
        self.closed = False

    def reauthenticate_first_enrollment_postcondition(
        self,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
        self.events.append("reauthenticate")
        self.reauthentication_calls += 1
        if self.error is not None:
            raise self.error
        return self.observed

    def close(self) -> None:
        self.events.append("close")
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


def _stub_confirmed_loader(
    monkeypatch: pytest.MonkeyPatch,
    values: list[TrustedTimeConfirmedFirstEnrollment],
) -> None:
    observed = iter(values)

    def load(**_: Any) -> TrustedTimeConfirmedFirstEnrollment:
        return next(observed)

    monkeypatch.setattr(staging, "load_confirmed_first_enrollment_evidence", load)


def test_prepare_returns_exact_non_authorizing_handoff_in_fixed_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    events: list[str] = []
    issuer = _Issuer(_observed_postcondition(), events)
    original_inventory = staging.require_no_retained_post_enrollment_start_claim
    original_bind = staging.bind_post_enrollment_start_reauthentication
    original_retain = staging.retain_post_enrollment_start_claim
    original_revalidate = staging.revalidate_retained_post_enrollment_start_claim

    def load(**_: Any) -> TrustedTimeConfirmedFirstEnrollment:
        events.append("load_enrollment")
        return approval.confirmed_enrollment

    def inventory(**kwargs: Any) -> None:
        events.append("inventory")
        original_inventory(**kwargs)

    def bind(**kwargs: Any) -> TrustedTimePostEnrollmentRuntimeReauthentication:
        events.append("bind")
        return original_bind(**kwargs)

    def retain(*args: Any, **kwargs: Any) -> Any:
        events.append("retain")
        assert issuer.closed
        return original_retain(*args, **kwargs)

    def revalidate(*args: Any, **kwargs: Any) -> bool:
        events.append("revalidate")
        return original_revalidate(*args, **kwargs)

    monkeypatch.setattr(staging, "load_confirmed_first_enrollment_evidence", load)
    monkeypatch.setattr(staging, "require_no_retained_post_enrollment_start_claim", inventory)
    monkeypatch.setattr(staging, "bind_post_enrollment_start_reauthentication", bind)
    monkeypatch.setattr(staging, "retain_post_enrollment_start_claim", retain)
    monkeypatch.setattr(staging, "revalidate_retained_post_enrollment_start_claim", revalidate)

    handoff = prepare_post_enrollment_start_release_under_lock(
        approval=approval,
        expected_approval_sha256=approval.approval_sha256,
        supervisor_container_id=SUPERVISOR_CONTAINER_ID,
        reauthentication_issuer=issuer,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    expected_argv = (
        "docker",
        "container",
        "exec",
        "--user",
        POST_ENROLLMENT_START_CONTAINER_USER,
        SUPERVISOR_CONTAINER_ID,
        POST_ENROLLMENT_START_RELEASE_COMMAND,
    )
    assert type(handoff) is TrustedTimePostEnrollmentStartStagingHandoff
    assert handoff.approval is approval
    assert handoff.approval_sha256 == approval.approval_sha256
    assert handoff.confirmed_enrollment == approval.confirmed_enrollment
    assert handoff.reauthentication == _reauthentication(approval)
    assert handoff.retained_claim.claim.approval is approval
    assert handoff.artifact_directory == artifact_directory
    assert handoff.ignored_root == ignored_root
    assert handoff.supervisor_container_id == SUPERVISOR_CONTAINER_ID
    assert handoff.release_argv == expected_argv
    assert post_enrollment_start_release_argv(SUPERVISOR_CONTAINER_ID) == expected_argv
    assert handoff.status == "claimed_release_handoff_unqualified"
    assert handoff.container_identity_authenticated is False
    assert handoff.topology_authenticated is False
    assert all(
        getattr(handoff, field_name) is False
        for field_name in (
            "authority_granted",
            "release_authorized",
            "persistent_start_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
            "operational_control_authorized",
            "readiness_authorized",
            "arming_authorized",
            "new_exposure_authorized",
            "broker_action_authorized",
            "paper_trading_authorized",
            "live_trading_authorized",
        )
    )
    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert events == [
        "inventory",
        "load_enrollment",
        "reauthenticate",
        "close",
        "bind",
        "load_enrollment",
        "inventory",
        "retain",
        "revalidate",
        "load_enrollment",
        "revalidate",
    ]


@pytest.mark.parametrize(
    ("digest", "container_id"),
    [
        ("g" * 64, SUPERVISOR_CONTAINER_ID),
        ("0" * 64, SUPERVISOR_CONTAINER_ID),
        (None, SUPERVISOR_CONTAINER_ID),
        ("approval", "a" * 63),
        ("approval", True),
    ],
)
def test_malformed_approval_digest_or_container_is_rejected_before_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    digest: object,
    container_id: object,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())
    inventory_called = False

    def inventory(**_: Any) -> None:
        nonlocal inventory_called
        inventory_called = True

    monkeypatch.setattr(staging, "require_no_retained_post_enrollment_start_claim", inventory)
    expected_digest = approval.approval_sha256 if digest == "approval" else digest

    with pytest.raises(
        TrustedTimePostEnrollmentStartStagingRejected,
        match="inputs are invalid",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=expected_digest,  # type: ignore[arg-type]
            supervisor_container_id=container_id,  # type: ignore[arg-type]
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert not inventory_called
    assert issuer.reauthentication_calls == 0
    assert issuer.close_calls == 0


def test_prior_different_operation_claim_requires_recovery_before_reauthentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    prior = retain_post_enrollment_start_claim(
        _claim(OTHER_OPERATION_ID),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())

    def unexpected_load(**_: Any) -> TrustedTimeConfirmedFirstEnrollment:
        raise AssertionError("enrollment evidence must not be loaded after claim consumption")

    monkeypatch.setattr(
        staging,
        "load_confirmed_first_enrollment_evidence",
        unexpected_load,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="claim requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert prior.artifact_path.name == POST_ENROLLMENT_START_CLAIM_FILE_NAME
    assert prior.artifact_path.read_bytes() == prior.encoded
    assert issuer.reauthentication_calls == 0
    assert issuer.close_calls == 1


@pytest.mark.parametrize("failure", ["drift", "load_error"])
def test_first_enrollment_evidence_failure_closes_owned_issuer_without_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())

    def fail_load(**_: Any) -> TrustedTimeConfirmedFirstEnrollment:
        if failure == "drift":
            return replace(approval.confirmed_enrollment, outcome_sha256="a" * 64)
        raise OSError("retained evidence unavailable")

    monkeypatch.setattr(staging, "load_confirmed_first_enrollment_evidence", fail_load)

    with pytest.raises(TrustedTimePostEnrollmentStartStagingRejected):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 0
    assert issuer.close_calls == 1
    assert issuer.closed
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_initial_claim_inventory_uncertainty_requires_recovery_and_closes_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())

    def fail_inventory(**_: Any) -> None:
        raise OSError("inventory unavailable")

    monkeypatch.setattr(
        staging,
        "require_no_retained_post_enrollment_start_claim",
        fail_inventory,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="claim state requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 0
    assert issuer.close_calls == 1
    assert issuer.closed
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize(
    "inventory_error",
    [
        TrustedTimePostEnrollmentStartClaimConsumed("already consumed"),
        TrustedTimePostEnrollmentStartClaimPersistenceError("inventory unavailable"),
    ],
)
def test_second_claim_inventory_race_requires_recovery_without_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory_error: Exception,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())
    inventory_calls = 0
    retain_called = False
    _stub_confirmed_loader(
        monkeypatch,
        [approval.confirmed_enrollment, approval.confirmed_enrollment],
    )

    def inventory(**_: Any) -> None:
        nonlocal inventory_calls
        inventory_calls += 1
        if inventory_calls == 2:
            raise inventory_error

    def retain(*_: Any, **__: Any) -> None:
        nonlocal retain_called
        retain_called = True
        raise AssertionError("claim retention must not follow an inventory race")

    monkeypatch.setattr(staging, "require_no_retained_post_enrollment_start_claim", inventory)
    monkeypatch.setattr(staging, "retain_post_enrollment_start_claim", retain)

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="claim state requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert inventory_calls == 2
    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert issuer.closed
    assert not retain_called
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_enrollment_evidence_drift_before_claim_is_rejected_without_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    drifted = replace(approval.confirmed_enrollment, outcome_sha256="a" * 64)
    issuer = _Issuer(_observed_postcondition())
    _stub_confirmed_loader(monkeypatch, [approval.confirmed_enrollment, drifted])

    with pytest.raises(
        TrustedTimePostEnrollmentStartStagingRejected,
        match="confirmed enrollment evidence changed",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_enrollment_evidence_drift_after_claim_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    drifted = replace(approval.confirmed_enrollment, outcome_sha256="a" * 64)
    issuer = _Issuer(_observed_postcondition())
    _stub_confirmed_loader(
        monkeypatch,
        [approval.confirmed_enrollment, approval.confirmed_enrollment, drifted],
    )

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="retained claim requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_reauthentication_mismatch_is_rejected_after_closing_without_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    observed = replace(_observed_postcondition(), host_identity_sha256="0" * 64)
    issuer = _Issuer(observed)
    _stub_confirmed_loader(monkeypatch, [approval.confirmed_enrollment])

    with pytest.raises(
        TrustedTimePostEnrollmentStartStagingRejected,
        match="staging preconditions are unavailable",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert issuer.closed
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_reauthentication_failure_still_closes_once_before_rejecting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition(), error=RuntimeError("provider unavailable"))
    _stub_confirmed_loader(monkeypatch, [approval.confirmed_enrollment])

    with pytest.raises(
        TrustedTimePostEnrollmentStartStagingRejected,
        match="runtime reauthentication is unavailable",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert issuer.closed


def test_close_failure_before_claim_is_rejected_without_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(
        _observed_postcondition(),
        close_error=OSError("close unconfirmed"),
    )
    _stub_confirmed_loader(monkeypatch, [approval.confirmed_enrollment])

    with pytest.raises(
        TrustedTimePostEnrollmentStartStagingRejected,
        match="issuer close is unconfirmed",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert not issuer.closed
    assert not (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_retention_failure_is_always_recovery_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())
    _stub_confirmed_loader(
        monkeypatch,
        [approval.confirmed_enrollment, approval.confirmed_enrollment],
    )

    def fail_retention(*_: Any, **__: Any) -> None:
        assert issuer.closed
        raise TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed("uncertain")

    monkeypatch.setattr(staging, "retain_post_enrollment_start_claim", fail_retention)

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="retained claim requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1


def test_revalidation_failure_leaves_claim_and_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    approval = _approval()
    issuer = _Issuer(_observed_postcondition())
    _stub_confirmed_loader(
        monkeypatch,
        [approval.confirmed_enrollment, approval.confirmed_enrollment],
    )
    monkeypatch.setattr(
        staging,
        "revalidate_retained_post_enrollment_start_claim",
        lambda *_args, **_kwargs: False,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimedRecoveryRequired,
        match="retained claim requires recovery",
    ):
        prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=approval.approval_sha256,
            supervisor_container_id=SUPERVISOR_CONTAINER_ID,
            reauthentication_issuer=issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert issuer.reauthentication_calls == 1
    assert issuer.close_calls == 1
    assert (artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_staging_module_has_no_execution_or_public_wiring_surface() -> None:
    assert not hasattr(staging, "main")
    assert not hasattr(staging, "release_main")
    assert not hasattr(staging, "run_local_topology")
    assert not hasattr(staging, "_run_docker")
    assert "subprocess" not in vars(staging)

    root = Path(staging.__file__).resolve().parents[1]
    assert "trusted_time_post_enrollment_staging" not in (root / "pyproject.toml").read_text()
    assert "trusted_time_post_enrollment_staging" not in (root / "Makefile").read_text()
