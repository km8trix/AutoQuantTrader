from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from packages.application.production_market_data_admission import (
    REQUIRED_PRODUCTION_EVIDENCE_ROLES,
    IndependentProductionEvidenceReview,
    ProductionEvidenceAttestation,
    ProductionEvidenceBlocker,
    ProductionEvidenceBundle,
    ProductionEvidenceClass,
    ProductionEvidenceDecision,
    ProductionEvidenceGateStatus,
    ProductionHistoricalSourceEvidenceSpecification,
    ProductionMarketDataEvidenceError,
    ProductionReviewDecision,
    assess_production_market_data_evidence,
)
from packages.market_data import (
    AdmissionEvidence,
    AdmissionSpecification,
    AdmissionStatus,
    ApprovalDecision,
    EntitlementStatus,
    IndependentApproval,
    SourceKind,
    TechnicalCheckEvidence,
    evaluate_admission,
)

FROZEN_AT = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
CHECKED_AT = datetime(2026, 8, 20, 13, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 8, 20, 15, 0, tzinfo=UTC)
VALID_THROUGH = datetime(2026, 9, 20, 0, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def test_generic_admission_report_cannot_upgrade_contract_only_prerequisites() -> None:
    """Caller-authored generic evidence is not the new typed prerequisite bundle."""

    required_checks = ("calendar", "corporate_actions", "identity", "raw_prices")
    generic_specification = AdmissionSpecification(
        specification_id="generic-admission-contract-fixture",
        source_id="tiingo-eod-production-v1",
        identifier_authority="identifier-authority-v1",
        universe_version="dia-iwm-qqq-spy-v1",
        calendar_version="calendar-v1",
        corporate_action_version="actions-v1",
        required_checks=required_checks,
        frozen_at=FROZEN_AT,
    )
    generic_evidence = AdmissionEvidence(
        source_id=generic_specification.source_id,
        source_kind=SourceKind.VENDOR,
        licensed=True,
        entitlement_status=EntitlementStatus.ACTIVE,
        terms_digest=_digest("contract-fixture-terms"),
        identifier_authority=generic_specification.identifier_authority,
        universe_version=generic_specification.universe_version,
        calendar_version=generic_specification.calendar_version,
        corporate_action_version=generic_specification.corporate_action_version,
        technical_checks=tuple(
            TechnicalCheckEvidence(
                check_id=check_id,
                passed=True,
                evidence_digest=_digest(f"contract-fixture-{check_id}"),
                checked_at=CHECKED_AT,
            )
            for check_id in required_checks
        ),
        executor_id="generic-contract-executor",
        evaluated_at=EVALUATED_AT,
        approval=IndependentApproval(
            reviewer_id="generic-contract-reviewer",
            decision=ApprovalDecision.APPROVED,
            reviewed_at=REVIEWED_AT,
        ),
    )
    generic_report = evaluate_admission(generic_specification, generic_evidence)
    assert generic_report.status is AdmissionStatus.ADMITTED

    production_specification = ProductionHistoricalSourceEvidenceSpecification(
        specification_id="production-prerequisite-contract-fixture",
        source_id=generic_specification.source_id,
        provider="tiingo",
        dataset="end-of-day-prices",
        feed="tiingo-eod",
        profile_sha256=_digest("production-profile"),
        scope_sha256=_digest("production-scope"),
        frozen_at=FROZEN_AT,
    )
    contract_only_bundle = ProductionEvidenceBundle(
        tuple(
            ProductionEvidenceAttestation(
                role=role,
                evidence_class=ProductionEvidenceClass.CONTRACT_ONLY,
                decision=ProductionEvidenceDecision.VERIFIED,
                evidence_id=f"contract-fixture-{role.value}",
                producer_id=f"contract-fixture-producer-{role.value}",
                source_id=production_specification.source_id,
                provider=production_specification.provider,
                dataset=production_specification.dataset,
                feed=production_specification.feed,
                profile_sha256=production_specification.profile_sha256,
                scope_sha256=production_specification.scope_sha256,
                artifact_sha256=_digest(f"contract-fixture-artifact-{role.value}"),
                observed_at=CHECKED_AT,
                valid_through=VALID_THROUGH,
            )
            for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES
        )
    )
    contract_only_review = IndependentProductionEvidenceReview(
        review_id="contract-fixture-review",
        reviewer_id="contract-fixture-independent-reviewer",
        evidence_class=ProductionEvidenceClass.CONTRACT_ONLY,
        decision=ProductionReviewDecision.APPROVED,
        source_id=production_specification.source_id,
        provider=production_specification.provider,
        dataset=production_specification.dataset,
        feed=production_specification.feed,
        profile_sha256=production_specification.profile_sha256,
        scope_sha256=production_specification.scope_sha256,
        evidence_bundle_sha256=contract_only_bundle.semantic_sha256,
        reviewed_at=REVIEWED_AT,
        valid_through=VALID_THROUGH,
    )

    assessment = assess_production_market_data_evidence(
        specification=production_specification,
        evidence=contract_only_bundle,
        review=contract_only_review,
        executor_id="production-gate-executor",
        evaluated_at=EVALUATED_AT,
    )

    assert assessment.status is ProductionEvidenceGateStatus.BLOCKED
    assert assessment.blockers == (
        ProductionEvidenceBlocker.NON_PRODUCTION_EVIDENCE,
        ProductionEvidenceBlocker.NON_PRODUCTION_REVIEW,
    )
    assert not assessment.historical_source_authorized
    assert not assessment.admission_authorized
    assert not assessment.trading_authorized
    with pytest.raises(ProductionMarketDataEvidenceError, match="exact evidence bundle"):
        assess_production_market_data_evidence(
            specification=production_specification,
            evidence=cast(Any, generic_report),
            review=None,
            executor_id="production-gate-executor",
            evaluated_at=EVALUATED_AT,
        )
