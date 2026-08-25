from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, cast

import pytest

from packages.application.production_market_data_admission import (
    REQUIRED_PRODUCTION_EVIDENCE_ROLES,
    IndependentProductionEvidenceReview,
    ProductionAuthorityEffect,
    ProductionEvidenceAttestation,
    ProductionEvidenceBlocker,
    ProductionEvidenceBundle,
    ProductionEvidenceClass,
    ProductionEvidenceDecision,
    ProductionEvidenceGateStatus,
    ProductionEvidenceRole,
    ProductionHistoricalSourceEvidenceSpecification,
    ProductionMarketDataEvidenceConflict,
    ProductionMarketDataEvidenceError,
    ProductionReviewDecision,
    assess_production_market_data_evidence,
)
from packages.market_data import HistoricalBarSource

FROZEN_AT = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
OBSERVED_AT = datetime(2026, 8, 20, 13, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 8, 20, 15, 0, tzinfo=UTC)
VALID_THROUGH = datetime(2026, 9, 20, 0, 0, tzinfo=UTC)
EXECUTOR_ID = "production-evidence-executor"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _specification() -> ProductionHistoricalSourceEvidenceSpecification:
    return ProductionHistoricalSourceEvidenceSpecification(
        specification_id="tiingo-eod-production-prerequisites-v1",
        source_id="tiingo-eod-production-v1",
        provider="tiingo",
        dataset="end-of-day-prices",
        feed="tiingo-eod",
        profile_sha256=_digest("frozen-production-profile"),
        scope_sha256=_digest("dia-iwm-qqq-spy-2026"),
        frozen_at=FROZEN_AT,
    )


def _attestation(
    role: ProductionEvidenceRole,
    *,
    evidence_class: ProductionEvidenceClass = ProductionEvidenceClass.EXTERNAL_AUTHORITY,
) -> ProductionEvidenceAttestation:
    specification = _specification()
    return ProductionEvidenceAttestation(
        role=role,
        evidence_class=evidence_class,
        decision=ProductionEvidenceDecision.VERIFIED,
        evidence_id=f"{role.value}-evidence-v1",
        producer_id=f"authority-{role.value}",
        source_id=specification.source_id,
        provider=specification.provider,
        dataset=specification.dataset,
        feed=specification.feed,
        profile_sha256=specification.profile_sha256,
        scope_sha256=specification.scope_sha256,
        artifact_sha256=_digest(f"artifact-{role.value}"),
        observed_at=OBSERVED_AT,
        valid_through=VALID_THROUGH,
    )


def _bundle(
    *,
    evidence_class: ProductionEvidenceClass = ProductionEvidenceClass.EXTERNAL_AUTHORITY,
) -> ProductionEvidenceBundle:
    return ProductionEvidenceBundle(
        tuple(
            _attestation(role, evidence_class=evidence_class)
            for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES
        )
    )


def _review(
    bundle: ProductionEvidenceBundle,
) -> IndependentProductionEvidenceReview:
    specification = _specification()
    return IndependentProductionEvidenceReview(
        review_id="production-prerequisite-review-v1",
        reviewer_id="independent-production-reviewer",
        evidence_class=ProductionEvidenceClass.EXTERNAL_AUTHORITY,
        decision=ProductionReviewDecision.APPROVED,
        source_id=specification.source_id,
        provider=specification.provider,
        dataset=specification.dataset,
        feed=specification.feed,
        profile_sha256=specification.profile_sha256,
        scope_sha256=specification.scope_sha256,
        evidence_bundle_sha256=bundle.semantic_sha256,
        reviewed_at=REVIEWED_AT,
        valid_through=VALID_THROUGH,
    )


def _assess(
    bundle: ProductionEvidenceBundle,
    *,
    review: IndependentProductionEvidenceReview | None = None,
    executor_id: str = EXECUTOR_ID,
    evaluated_at: datetime = EVALUATED_AT,
):
    if review is None:
        review = _review(bundle)
    return assess_production_market_data_evidence(
        specification=_specification(),
        evidence=bundle,
        review=review,
        executor_id=executor_id,
        evaluated_at=evaluated_at,
    )


def test_complete_external_shaped_inventory_is_only_ready_for_admission_evaluation() -> None:
    bundle = _bundle()
    assessment = _assess(bundle)

    assert assessment.status is ProductionEvidenceGateStatus.READY_FOR_ADMISSION_EVALUATION
    assert assessment.ready_for_admission_evaluation
    assert assessment.blockers == ()
    assert assessment.historical_source_effect is ProductionAuthorityEffect.NONE
    assert assessment.admission_effect is ProductionAuthorityEffect.NONE
    assert assessment.canonical_market_data_effect is ProductionAuthorityEffect.NONE
    assert assessment.trading_effect is ProductionAuthorityEffect.NONE
    assert not assessment.historical_source_authorized
    assert not assessment.admission_authorized
    assert not assessment.trading_authorized
    assert not isinstance(assessment, HistoricalBarSource)
    assert not hasattr(assessment, "load")


@pytest.mark.parametrize(
    ("missing_role", "expected_blocker"),
    (
        (
            ProductionEvidenceRole.IDENTITY_LIFECYCLE,
            ProductionEvidenceBlocker.IDENTITY_LIFECYCLE_EVIDENCE_MISSING,
        ),
        (
            ProductionEvidenceRole.CALENDAR,
            ProductionEvidenceBlocker.CALENDAR_EVIDENCE_MISSING,
        ),
        (
            ProductionEvidenceRole.CORPORATE_ACTIONS,
            ProductionEvidenceBlocker.CORPORATE_ACTION_EVIDENCE_MISSING,
        ),
        (
            ProductionEvidenceRole.RAW_PRICE_PROVENANCE,
            ProductionEvidenceBlocker.RAW_PRICE_PROVENANCE_EVIDENCE_MISSING,
        ),
        (
            ProductionEvidenceRole.LICENSE_RIGHTS,
            ProductionEvidenceBlocker.LICENSE_RIGHTS_EVIDENCE_MISSING,
        ),
    ),
)
def test_each_missing_production_evidence_role_fails_closed(
    missing_role: ProductionEvidenceRole,
    expected_blocker: ProductionEvidenceBlocker,
) -> None:
    bundle = ProductionEvidenceBundle(
        tuple(
            _attestation(role)
            for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES
            if role is not missing_role
        )
    )

    assessment = _assess(bundle)

    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED
    assert not assessment.ready_for_admission_evaluation
    assert expected_blocker in assessment.blockers
    assert not assessment.historical_source_authorized


def test_empty_inventory_reports_every_missing_role_and_review_in_fixed_order() -> None:
    assessment = assess_production_market_data_evidence(
        specification=_specification(),
        evidence=ProductionEvidenceBundle(()),
        review=None,
        executor_id=EXECUTOR_ID,
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.blockers == (
        ProductionEvidenceBlocker.IDENTITY_LIFECYCLE_EVIDENCE_MISSING,
        ProductionEvidenceBlocker.CALENDAR_EVIDENCE_MISSING,
        ProductionEvidenceBlocker.CORPORATE_ACTION_EVIDENCE_MISSING,
        ProductionEvidenceBlocker.RAW_PRICE_PROVENANCE_EVIDENCE_MISSING,
        ProductionEvidenceBlocker.LICENSE_RIGHTS_EVIDENCE_MISSING,
        ProductionEvidenceBlocker.INDEPENDENT_REVIEW_MISSING,
    )


@pytest.mark.parametrize(
    "evidence_class",
    (
        ProductionEvidenceClass.SYNTHETIC_CONTRACT,
        ProductionEvidenceClass.RESEARCH_CAPTURE,
        ProductionEvidenceClass.CONTRACT_ONLY,
        ProductionEvidenceClass.RECORDED_FIXTURE,
    ),
)
def test_synthetic_research_and_contract_evidence_never_satisfy_production_gate(
    evidence_class: ProductionEvidenceClass,
) -> None:
    bundle = _bundle(evidence_class=evidence_class)

    assessment = _assess(bundle)

    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED
    assert ProductionEvidenceBlocker.NON_PRODUCTION_EVIDENCE in assessment.blockers
    assert not assessment.admission_authorized


@pytest.mark.parametrize(
    ("changes", "expected_blocker"),
    (
        ({"source_id": "other-source"}, ProductionEvidenceBlocker.SOURCE_BINDING_MISMATCH),
        ({"provider": "other-provider"}, ProductionEvidenceBlocker.PROVIDER_BINDING_MISMATCH),
        ({"dataset": "other-dataset"}, ProductionEvidenceBlocker.DATASET_BINDING_MISMATCH),
        ({"feed": "other-feed"}, ProductionEvidenceBlocker.FEED_BINDING_MISMATCH),
        (
            {"profile_sha256": _digest("other-profile")},
            ProductionEvidenceBlocker.PROFILE_BINDING_MISMATCH,
        ),
        (
            {"scope_sha256": _digest("other-scope")},
            ProductionEvidenceBlocker.SCOPE_BINDING_MISMATCH,
        ),
    ),
)
def test_cross_artifact_binding_mismatches_fail_closed(
    changes: dict[str, object],
    expected_blocker: ProductionEvidenceBlocker,
) -> None:
    bundle = _bundle()
    first = replace(bundle.attestations[0], **cast(Any, changes))
    mismatched = ProductionEvidenceBundle((first, *bundle.attestations[1:]))

    assessment = _assess(mismatched)

    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED
    assert expected_blocker in assessment.blockers


@pytest.mark.parametrize(
    "valid_through",
    (
        EVALUATED_AT,
        datetime(2026, 8, 20, 14, 59, 59, tzinfo=UTC),
    ),
)
def test_evidence_is_stale_at_and_after_its_half_open_validity_boundary(
    valid_through: datetime,
) -> None:
    bundle = _bundle()
    stale = replace(bundle.attestations[0], valid_through=valid_through)
    stale_bundle = ProductionEvidenceBundle((stale, *bundle.attestations[1:]))

    assessment = _assess(stale_bundle)

    assert ProductionEvidenceBlocker.EVIDENCE_STALE in assessment.blockers
    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED


def test_pre_freeze_and_future_observations_fail_closed() -> None:
    bundle = _bundle()
    predating = replace(
        bundle.attestations[0],
        observed_at=datetime(2026, 8, 20, 11, 59, tzinfo=UTC),
    )
    future = replace(
        bundle.attestations[1],
        observed_at=datetime(2026, 8, 20, 15, 1, tzinfo=UTC),
    )
    impossible = ProductionEvidenceBundle((predating, future, *bundle.attestations[2:]))

    assessment = _assess(impossible)

    assert ProductionEvidenceBlocker.EVIDENCE_PREDATES_SPECIFICATION in assessment.blockers
    assert ProductionEvidenceBlocker.EVIDENCE_OBSERVED_IN_FUTURE in assessment.blockers


@pytest.mark.parametrize(
    "reviewer_id",
    (
        EXECUTOR_ID,
        f"authority-{ProductionEvidenceRole.CALENDAR.value}",
    ),
)
def test_executor_or_evidence_producer_cannot_approve_the_bundle(reviewer_id: str) -> None:
    bundle = _bundle()
    self_review = replace(_review(bundle), reviewer_id=reviewer_id)

    assessment = _assess(bundle, review=self_review)

    assert ProductionEvidenceBlocker.SELF_APPROVED in assessment.blockers
    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED


@pytest.mark.parametrize(
    ("changes", "expected_blocker"),
    (
        (
            {"evidence_bundle_sha256": _digest("other-bundle")},
            ProductionEvidenceBlocker.REVIEW_BUNDLE_MISMATCH,
        ),
        (
            {"source_id": "other-source"},
            ProductionEvidenceBlocker.REVIEW_BINDING_MISMATCH,
        ),
        (
            {"profile_sha256": _digest("other-profile")},
            ProductionEvidenceBlocker.REVIEW_BINDING_MISMATCH,
        ),
        (
            {"scope_sha256": _digest("other-scope")},
            ProductionEvidenceBlocker.REVIEW_BINDING_MISMATCH,
        ),
        (
            {"evidence_class": ProductionEvidenceClass.SYNTHETIC_CONTRACT},
            ProductionEvidenceBlocker.NON_PRODUCTION_REVIEW,
        ),
        (
            {"decision": ProductionReviewDecision.REJECTED},
            ProductionEvidenceBlocker.REVIEW_REJECTED,
        ),
        (
            {"valid_through": EVALUATED_AT},
            ProductionEvidenceBlocker.REVIEW_STALE,
        ),
    ),
)
def test_unbound_synthetic_rejected_or_stale_review_fails_closed(
    changes: dict[str, object],
    expected_blocker: ProductionEvidenceBlocker,
) -> None:
    bundle = _bundle()
    invalid_review = replace(_review(bundle), **cast(Any, changes))

    assessment = _assess(bundle, review=invalid_review)

    assert expected_blocker in assessment.blockers
    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED


def test_review_must_follow_all_evidence_and_not_postdate_evaluation() -> None:
    bundle = _bundle()
    early = replace(
        _review(bundle),
        reviewed_at=datetime(2026, 8, 20, 12, 59, tzinfo=UTC),
    )
    future = replace(
        _review(bundle),
        reviewed_at=datetime(2026, 8, 20, 15, 1, tzinfo=UTC),
    )

    early_assessment = _assess(bundle, review=early)
    future_assessment = _assess(bundle, review=future)

    assert ProductionEvidenceBlocker.REVIEW_PREDATES_EVIDENCE in early_assessment.blockers
    assert ProductionEvidenceBlocker.REVIEW_OBSERVED_IN_FUTURE in future_assessment.blockers


def test_duplicate_role_and_rejected_evidence_fail_closed() -> None:
    bundle = _bundle()
    rejected = replace(
        bundle.attestations[0],
        decision=ProductionEvidenceDecision.REJECTED,
    )
    duplicated = ProductionEvidenceBundle(
        (rejected, *bundle.attestations, _attestation(ProductionEvidenceRole.CALENDAR))
    )

    assessment = _assess(duplicated)

    assert ProductionEvidenceBlocker.DUPLICATE_EVIDENCE_ROLE in assessment.blockers
    assert ProductionEvidenceBlocker.EVIDENCE_REJECTED in assessment.blockers


def test_bundle_and_assessment_identity_are_order_independent_and_deterministic() -> None:
    forward = _bundle()
    reverse = ProductionEvidenceBundle(tuple(reversed(forward.attestations)))

    first = _assess(forward)
    second = _assess(reverse, review=_review(reverse))

    assert forward.semantic_sha256 == reverse.semantic_sha256
    assert first == second
    assert first.report_id == second.report_id
    assert first.semantic_sha256 == second.semantic_sha256


def test_contracts_are_immutable_exact_typed_and_assessments_are_sealed() -> None:
    bundle = _bundle()
    assessment = _assess(bundle)

    with pytest.raises(FrozenInstanceError):
        assessment.blockers = ()  # type: ignore[misc]
    with pytest.raises(ProductionMarketDataEvidenceError, match="exact immutable tuple"):
        ProductionEvidenceBundle(cast(Any, list(bundle.attestations)))
    with pytest.raises(ProductionMarketDataEvidenceError, match="exact ProductionEvidenceRole"):
        replace(bundle.attestations[0], role="production_calendar")  # type: ignore[arg-type]
    with pytest.raises(ProductionMarketDataEvidenceConflict, match="seal is invalid"):
        replace(
            assessment,
            blockers=(ProductionEvidenceBlocker.NON_PRODUCTION_EVIDENCE,),
        )


def test_naive_timestamps_and_invalid_digests_are_rejected() -> None:
    bundle = _bundle()

    with pytest.raises(ProductionMarketDataEvidenceError, match="timezone-aware"):
        replace(bundle.attestations[0], observed_at=datetime(2026, 8, 20, 13, 0))
    with pytest.raises(ProductionMarketDataEvidenceError, match="SHA-256"):
        replace(_specification(), profile_sha256="not-a-digest")
    with pytest.raises(ProductionMarketDataEvidenceError, match="nonzero"):
        replace(_specification(), profile_sha256="0" * 64)
    with pytest.raises(ProductionMarketDataEvidenceError, match="stored in UTC"):
        replace(
            bundle.attestations[0],
            observed_at=datetime(
                2026,
                8,
                20,
                14,
                0,
                tzinfo=timezone(timedelta(hours=1)),
            ),
        )
