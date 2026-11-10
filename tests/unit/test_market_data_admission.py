from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from packages.market_data.admission import (
    AdmissionEvidence,
    AdmissionEvidenceError,
    AdmissionSpecification,
    AdmissionStatus,
    ApprovalDecision,
    EntitlementStatus,
    IndependentApproval,
    SourceKind,
    TechnicalCheckEvidence,
    evaluate_admission,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
FROZEN_AT = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 7, 15, 14, 0, tzinfo=UTC)


def specification(
    *,
    required_checks: tuple[str, ...] = ("causal_revisions", "calendar_edges"),
) -> AdmissionSpecification:
    return AdmissionSpecification(
        specification_id="phase1-vendor-admission-v1",
        source_id="licensed-pit-bars-v1",
        identifier_authority="authority-v1",
        universe_version="liquid-etf-v1",
        calendar_version="xnys-2026a",
        corporate_action_version="actions-2026a",
        required_checks=required_checks,
        frozen_at=FROZEN_AT,
    )


def technical_checks(
    *,
    causal_passed: bool = True,
    reverse: bool = False,
) -> tuple[TechnicalCheckEvidence, ...]:
    values = (
        TechnicalCheckEvidence(
            check_id="causal_revisions",
            passed=causal_passed,
            evidence_digest=DIGEST_A,
            checked_at=datetime(2026, 7, 15, 13, 0, tzinfo=UTC),
        ),
        TechnicalCheckEvidence(
            check_id="calendar_edges",
            passed=True,
            evidence_digest=DIGEST_B,
            checked_at=datetime(2026, 7, 15, 13, 1, tzinfo=UTC),
        ),
    )
    return tuple(reversed(values)) if reverse else values


def approval(
    *,
    reviewer_id: str = "independent-reviewer",
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
) -> IndependentApproval:
    return IndependentApproval(
        reviewer_id=reviewer_id,
        decision=decision,
        reviewed_at=datetime(2026, 7, 15, 13, 30, tzinfo=UTC),
    )


def evidence(
    *,
    source_kind: SourceKind = SourceKind.VENDOR,
    licensed: bool = True,
    entitlement_status: EntitlementStatus = EntitlementStatus.ACTIVE,
    terms_digest: str | None = DIGEST_C,
    identifier_authority: str | None = "authority-v1",
    universe_version: str | None = "liquid-etf-v1",
    calendar_version: str | None = "xnys-2026a",
    corporate_action_version: str | None = "actions-2026a",
    checks: tuple[TechnicalCheckEvidence, ...] | None = None,
    independent_approval: IndependentApproval | None = None,
) -> AdmissionEvidence:
    return AdmissionEvidence(
        source_id="licensed-pit-bars-v1",
        source_kind=source_kind,
        licensed=licensed,
        entitlement_status=entitlement_status,
        terms_digest=terms_digest,
        identifier_authority=identifier_authority,
        universe_version=universe_version,
        calendar_version=calendar_version,
        corporate_action_version=corporate_action_version,
        technical_checks=technical_checks() if checks is None else checks,
        executor_id="adapter-executor",
        evaluated_at=EVALUATED_AT,
        approval=independent_approval,
    )


def test_vendor_is_admitted_only_with_complete_independently_approved_evidence() -> None:
    report = evaluate_admission(
        specification(),
        evidence(independent_approval=approval()),
    )

    assert report.status is AdmissionStatus.ADMITTED
    assert report.run_id.startswith("admission-")
    assert len(report.evidence_digest) == 64
    assert len(report.report_digest) == 64
    assert all(check.status != "failed" for check in report.checks)
    assert (
        next(
            check for check in report.checks if check.check_id == "technical:causal_revisions"
        ).evidence_digest
        == DIGEST_A
    )


@pytest.mark.parametrize(
    "source_kind",
    [SourceKind.SYNTHETIC_FIXTURE, SourceKind.RECORDED_FIXTURE],
)
def test_fixtures_remain_blocked_even_when_every_other_gate_passes(
    source_kind: SourceKind,
) -> None:
    report = evaluate_admission(
        specification(),
        evidence(source_kind=source_kind, independent_approval=approval()),
    )

    assert report.status is AdmissionStatus.BLOCKED
    assert next(check for check in report.checks if check.check_id == "source_kind").status == (
        "failed"
    )


def test_blocked_prerequisite_precedence_preserves_other_rejection_evidence() -> None:
    report = evaluate_admission(
        specification(),
        evidence(
            source_kind=SourceKind.SYNTHETIC_FIXTURE,
            checks=technical_checks(causal_passed=False),
            independent_approval=approval(decision=ApprovalDecision.REJECTED),
        ),
    )

    assert report.status is AdmissionStatus.BLOCKED
    failures = {check.check_id for check in report.checks if check.status == "failed"}
    assert failures >= {
        "source_kind",
        "technical:causal_revisions",
        "independent_approval",
    }


@pytest.mark.parametrize(
    ("changes", "failed_check"),
    [
        ({"licensed": False}, "licensed"),
        ({"entitlement_status": EntitlementStatus.EXPIRED}, "entitlement"),
        ({"terms_digest": None}, "terms_digest"),
        ({"identifier_authority": None}, "identifier_authority"),
        ({"identifier_authority": "other-authority"}, "identifier_authority"),
        ({"universe_version": None}, "universe_version"),
        ({"universe_version": "other-universe"}, "universe_version"),
        ({"calendar_version": None}, "calendar_version"),
        ({"calendar_version": "other-calendar"}, "calendar_version"),
        ({"corporate_action_version": None}, "corporate_action_version"),
        ({"corporate_action_version": "other-actions"}, "corporate_action_version"),
    ],
)
def test_missing_or_mismatched_source_prerequisites_are_blocked(
    changes: dict[str, object],
    failed_check: str,
) -> None:
    base = evidence(independent_approval=approval())
    report = evaluate_admission(specification(), replace(base, **cast(Any, changes)))

    assert report.status is AdmissionStatus.BLOCKED
    assert next(check for check in report.checks if check.check_id == failed_check).status == (
        "failed"
    )


def test_evidence_for_a_different_source_cannot_satisfy_the_specification() -> None:
    wrong_source = replace(evidence(independent_approval=approval()), source_id="other-vendor")

    report = evaluate_admission(specification(), wrong_source)
    admitted = evaluate_admission(specification(), evidence(independent_approval=approval()))

    assert report.status is AdmissionStatus.BLOCKED
    assert report.run_id != admitted.run_id
    assert report.evidence_digest != admitted.evidence_digest
    assert report.report_digest != admitted.report_digest
    source_check = next(check for check in report.checks if check.check_id == "source_id")
    assert source_check.status == "failed"
    assert "other-vendor" in source_check.detail


def test_complete_technical_evidence_without_approval_is_review_pending() -> None:
    report = evaluate_admission(specification(), evidence())

    assert report.status is AdmissionStatus.REVIEW_PENDING
    approval_check = next(
        check for check in report.checks if check.check_id == "independent_approval"
    )
    assert approval_check.status == "pending"


def test_executor_cannot_approve_their_own_admission() -> None:
    report = evaluate_admission(
        specification(),
        evidence(independent_approval=approval(reviewer_id="adapter-executor")),
    )

    assert report.status is AdmissionStatus.REVIEW_PENDING
    assert "differ" in next(
        check.detail for check in report.checks if check.check_id == "independent_approval"
    )


def test_failed_required_check_rejects_an_otherwise_eligible_vendor() -> None:
    report = evaluate_admission(
        specification(),
        evidence(
            checks=technical_checks(causal_passed=False),
            independent_approval=approval(),
        ),
    )

    assert report.status is AdmissionStatus.REJECTED
    assert (
        next(
            check for check in report.checks if check.check_id == "technical:causal_revisions"
        ).status
        == "failed"
    )


def test_independent_reviewer_can_reject_technically_passing_evidence() -> None:
    report = evaluate_admission(
        specification(),
        evidence(independent_approval=approval(decision=ApprovalDecision.REJECTED)),
    )

    assert report.status is AdmissionStatus.REJECTED


def test_run_and_report_digests_ignore_input_check_order() -> None:
    first = evaluate_admission(
        specification(required_checks=("calendar_edges", "causal_revisions")),
        evidence(checks=technical_checks(), independent_approval=approval()),
    )
    second = evaluate_admission(
        specification(required_checks=("causal_revisions", "calendar_edges")),
        evidence(checks=technical_checks(reverse=True), independent_approval=approval()),
    )

    assert first.run_id == second.run_id
    assert first.report_digest == second.report_digest
    assert first.checks == second.checks


def test_a_material_evidence_change_changes_both_deterministic_identifiers() -> None:
    passing = evaluate_admission(specification(), evidence(independent_approval=approval()))
    failing = evaluate_admission(
        specification(),
        evidence(
            checks=technical_checks(causal_passed=False),
            independent_approval=approval(),
        ),
    )

    assert passing.run_id != failing.run_id
    assert passing.evidence_digest != failing.evidence_digest
    assert passing.report_digest != failing.report_digest


def test_missing_duplicate_and_unknown_technical_checks_are_rejected() -> None:
    complete = technical_checks()
    cases = (
        (complete[:1], "missing required checks"),
        ((*complete, complete[0]), "duplicate required checks"),
        (
            (
                *complete,
                TechnicalCheckEvidence(
                    check_id="not-required",
                    passed=True,
                    evidence_digest=DIGEST_C,
                    checked_at=EVALUATED_AT,
                ),
            ),
            "unknown required checks",
        ),
    )

    for checks, message in cases:
        with pytest.raises(AdmissionEvidenceError, match=message):
            evaluate_admission(specification(), evidence(checks=checks))


def test_specification_rejects_empty_or_duplicate_required_checks() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        specification(required_checks=())
    with pytest.raises(ValueError, match="duplicates"):
        specification(required_checks=("calendar_edges", "calendar_edges"))


@pytest.mark.parametrize("field", ["frozen_at", "evaluated_at", "checked_at", "reviewed_at"])
def test_naive_admission_timestamps_are_rejected(field: str) -> None:
    naive = datetime(2026, 7, 15, 12, 0)

    if field == "frozen_at":
        with pytest.raises(ValueError, match="timezone-aware"):
            replace(specification(), frozen_at=naive)
    elif field == "evaluated_at":
        with pytest.raises(ValueError, match="timezone-aware"):
            replace(evidence(), evaluated_at=naive)
    elif field == "checked_at":
        with pytest.raises(ValueError, match="timezone-aware"):
            replace(technical_checks()[0], checked_at=naive)
    else:
        with pytest.raises(ValueError, match="timezone-aware"):
            replace(approval(), reviewed_at=naive)


def test_technical_checks_must_follow_the_frozen_specification() -> None:
    frozen_late = replace(
        specification(),
        frozen_at=datetime(2026, 7, 15, 13, 0, 1, tzinfo=UTC),
    )

    with pytest.raises(AdmissionEvidenceError, match="predates the frozen specification"):
        evaluate_admission(frozen_late, evidence())


def test_technical_checks_cannot_postdate_the_evaluation() -> None:
    first, second = technical_checks()
    future_check = replace(
        second,
        checked_at=datetime(2026, 7, 15, 14, 0, 1, tzinfo=UTC),
    )

    with pytest.raises(AdmissionEvidenceError, match="occurs after evaluated_at"):
        evaluate_admission(specification(), evidence(checks=(first, future_check)))


def test_independent_approval_must_follow_all_checks_and_not_postdate_evaluation() -> None:
    too_early = replace(
        approval(),
        reviewed_at=datetime(2026, 7, 15, 13, 0, 30, tzinfo=UTC),
    )
    too_late = replace(
        approval(),
        reviewed_at=datetime(2026, 7, 15, 14, 0, 1, tzinfo=UTC),
    )

    with pytest.raises(AdmissionEvidenceError, match="predates the technical evidence"):
        evaluate_admission(specification(), evidence(independent_approval=too_early))
    with pytest.raises(AdmissionEvidenceError, match="occurs after evaluated_at"):
        evaluate_admission(specification(), evidence(independent_approval=too_late))


def test_terms_and_technical_evidence_require_sha256_digests() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        evidence(terms_digest="not-a-digest")
    with pytest.raises(ValueError, match="SHA-256"):
        replace(technical_checks()[0], evidence_digest="not-a-digest")


def test_admission_contracts_are_immutable() -> None:
    report = evaluate_admission(specification(), evidence(independent_approval=approval()))

    with pytest.raises(FrozenInstanceError):
        report.status = AdmissionStatus.BLOCKED  # type: ignore[misc]


def test_typed_enums_and_tuple_collections_are_enforced_at_runtime() -> None:
    with pytest.raises(ValueError, match="SourceKind"):
        replace(evidence(), source_kind="vendor")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="immutable tuple"):
        replace(specification(), required_checks=["calendar_edges"])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="immutable tuple"):
        replace(evidence(), technical_checks=list(technical_checks()))  # type: ignore[arg-type]
