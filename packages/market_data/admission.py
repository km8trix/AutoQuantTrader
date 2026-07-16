"""Pure qualification rules for admitting an external market-data source.

Admission is intentionally separate from ingestion and persistence.  An adapter
may produce technically valid facts without being licensed or independently
approved, and local fixtures can never acquire vendor readiness through this
evaluator.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from packages.market_data.models import require_digest, require_text, require_utc


class AdmissionEvidenceError(ValueError):
    """Admission evidence is incomplete, ambiguous, or outside the specification."""


class AdmissionStatus(StrEnum):
    BLOCKED = "blocked"
    REVIEW_PENDING = "review_pending"
    ADMITTED = "admitted"
    REJECTED = "rejected"


class AdmissionCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"


class SourceKind(StrEnum):
    VENDOR = "vendor"
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    RECORDED_FIXTURE = "recorded_fixture"


class EntitlementStatus(StrEnum):
    ACTIVE = "active"
    FIXTURE_ONLY = "fixture_only"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class AdmissionSpecification:
    """The frozen identity and technical checks required by one admission run."""

    specification_id: str
    source_id: str
    identifier_authority: str
    universe_version: str
    calendar_version: str
    corporate_action_version: str
    required_checks: tuple[str, ...]
    frozen_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.specification_id, "specification_id"),
            (self.source_id, "source_id"),
            (self.identifier_authority, "identifier_authority"),
            (self.universe_version, "universe_version"),
            (self.calendar_version, "calendar_version"),
            (self.corporate_action_version, "corporate_action_version"),
        ):
            require_text(value, field_name)
        require_utc(self.frozen_at, "frozen_at")
        if type(self.required_checks) is not tuple:
            raise ValueError("required_checks must be an immutable tuple")
        if not self.required_checks:
            raise ValueError("required_checks cannot be empty")
        for check_id in self.required_checks:
            require_text(check_id, "required check ID")
        if len(set(self.required_checks)) != len(self.required_checks):
            raise ValueError("required_checks cannot contain duplicates")


@dataclass(frozen=True, slots=True)
class TechnicalCheckEvidence:
    """The immutable result and evidence digest for one required technical check."""

    check_id: str
    passed: bool
    evidence_digest: str
    checked_at: datetime

    def __post_init__(self) -> None:
        require_text(self.check_id, "check_id")
        if type(self.passed) is not bool:
            raise ValueError("passed must be a boolean")
        require_digest(self.evidence_digest, "evidence_digest")
        require_utc(self.checked_at, "checked_at")


@dataclass(frozen=True, slots=True)
class IndependentApproval:
    """A human review decision, whose independence is checked by the evaluator."""

    reviewer_id: str
    decision: ApprovalDecision
    reviewed_at: datetime

    def __post_init__(self) -> None:
        require_text(self.reviewer_id, "reviewer_id")
        if not isinstance(self.decision, ApprovalDecision):
            raise ValueError("decision must be an ApprovalDecision")
        require_utc(self.reviewed_at, "reviewed_at")


@dataclass(frozen=True, slots=True)
class AdmissionEvidence:
    """Canonical evidence supplied for one source against one specification."""

    source_id: str
    source_kind: SourceKind
    licensed: bool
    entitlement_status: EntitlementStatus
    terms_digest: str | None
    identifier_authority: str | None
    universe_version: str | None
    calendar_version: str | None
    corporate_action_version: str | None
    technical_checks: tuple[TechnicalCheckEvidence, ...]
    executor_id: str
    evaluated_at: datetime
    approval: IndependentApproval | None = None

    def __post_init__(self) -> None:
        require_text(self.source_id, "source_id")
        require_text(self.executor_id, "executor_id")
        if not isinstance(self.source_kind, SourceKind):
            raise ValueError("source_kind must be a SourceKind")
        if not isinstance(self.entitlement_status, EntitlementStatus):
            raise ValueError("entitlement_status must be an EntitlementStatus")
        if type(self.licensed) is not bool:
            raise ValueError("licensed must be a boolean")
        if self.terms_digest is not None:
            require_digest(self.terms_digest, "terms_digest")
        for value, field_name in (
            (self.identifier_authority, "identifier_authority"),
            (self.universe_version, "universe_version"),
            (self.calendar_version, "calendar_version"),
            (self.corporate_action_version, "corporate_action_version"),
        ):
            if value is not None:
                require_text(value, field_name)
        if type(self.technical_checks) is not tuple or not all(
            isinstance(check, TechnicalCheckEvidence) for check in self.technical_checks
        ):
            raise ValueError("technical_checks must be an immutable tuple of check evidence")
        if self.approval is not None and not isinstance(self.approval, IndependentApproval):
            raise ValueError("approval must be an IndependentApproval")
        require_utc(self.evaluated_at, "evaluated_at")


@dataclass(frozen=True, slots=True)
class AdmissionCheck:
    """One explanatory gate in a deterministic admission report."""

    check_id: str
    status: AdmissionCheckStatus
    detail: str
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        require_text(self.check_id, "check_id")
        require_text(self.detail, "detail")
        if not isinstance(self.status, AdmissionCheckStatus):
            raise ValueError("status must be an AdmissionCheckStatus")
        if self.evidence_digest is not None:
            require_digest(self.evidence_digest, "evidence_digest")


@dataclass(frozen=True, slots=True)
class AdmissionReport:
    """A deterministic decision over an immutable evidence set."""

    run_id: str
    evidence_digest: str
    report_digest: str
    specification_id: str
    source_id: str
    status: AdmissionStatus
    evaluated_at: datetime
    checks: tuple[AdmissionCheck, ...]

    def __post_init__(self) -> None:
        require_text(self.run_id, "run_id")
        require_digest(self.evidence_digest, "evidence_digest")
        require_digest(self.report_digest, "report_digest")
        require_text(self.specification_id, "specification_id")
        require_text(self.source_id, "source_id")
        if not isinstance(self.status, AdmissionStatus):
            raise ValueError("status must be an AdmissionStatus")
        require_utc(self.evaluated_at, "evaluated_at")
        if type(self.checks) is not tuple or not all(
            isinstance(check, AdmissionCheck) for check in self.checks
        ):
            raise ValueError("checks must be an immutable tuple of admission checks")
        if not self.checks:
            raise ValueError("an admission report must contain checks")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_technical_evidence(
    specification: AdmissionSpecification,
    evidence: AdmissionEvidence,
) -> dict[str, TechnicalCheckEvidence]:
    checks: dict[str, TechnicalCheckEvidence] = {}
    duplicates: set[str] = set()
    for check in evidence.technical_checks:
        if check.check_id in checks:
            duplicates.add(check.check_id)
        checks[check.check_id] = check
    if duplicates:
        raise AdmissionEvidenceError(f"duplicate required checks: {', '.join(sorted(duplicates))}")

    required = set(specification.required_checks)
    provided = set(checks)
    missing = required - provided
    unknown = provided - required
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing required checks: {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown required checks: {', '.join(sorted(unknown))}")
        raise AdmissionEvidenceError("; ".join(details))
    return checks


def _validate_temporal_evidence(
    specification: AdmissionSpecification,
    evidence: AdmissionEvidence,
    technical: dict[str, TechnicalCheckEvidence],
) -> None:
    for check_id in sorted(technical):
        checked_at = technical[check_id].checked_at
        if checked_at < specification.frozen_at:
            raise AdmissionEvidenceError(
                f"technical check {check_id!r} predates the frozen specification"
            )
        if checked_at > evidence.evaluated_at:
            raise AdmissionEvidenceError(f"technical check {check_id!r} occurs after evaluated_at")

    approval = evidence.approval
    if approval is None:
        return
    latest_check_at = max(check.checked_at for check in technical.values())
    if approval.reviewed_at < latest_check_at:
        raise AdmissionEvidenceError("independent approval predates the technical evidence")
    if approval.reviewed_at > evidence.evaluated_at:
        raise AdmissionEvidenceError("independent approval occurs after evaluated_at")


def _gate(
    check_id: str,
    passed: bool,
    passed_detail: str,
    failed_detail: str,
    *,
    evidence_digest: str | None = None,
) -> AdmissionCheck:
    return AdmissionCheck(
        check_id=check_id,
        status=AdmissionCheckStatus.PASSED if passed else AdmissionCheckStatus.FAILED,
        detail=passed_detail if passed else failed_detail,
        evidence_digest=evidence_digest,
    )


def _canonical_input(
    specification: AdmissionSpecification,
    evidence: AdmissionEvidence,
    technical: dict[str, TechnicalCheckEvidence],
) -> dict[str, Any]:
    approval = evidence.approval
    return {
        "evidence": {
            "approval": (
                None
                if approval is None
                else {
                    "decision": approval.decision.value,
                    "reviewed_at": _timestamp(approval.reviewed_at),
                    "reviewer_id": approval.reviewer_id,
                }
            ),
            "calendar_version": evidence.calendar_version,
            "corporate_action_version": evidence.corporate_action_version,
            "entitlement_status": evidence.entitlement_status.value,
            "evaluated_at": _timestamp(evidence.evaluated_at),
            "executor_id": evidence.executor_id,
            "identifier_authority": evidence.identifier_authority,
            "licensed": evidence.licensed,
            "source_id": evidence.source_id,
            "source_kind": evidence.source_kind.value,
            "technical_checks": [
                {
                    "check_id": check_id,
                    "checked_at": _timestamp(technical[check_id].checked_at),
                    "evidence_digest": technical[check_id].evidence_digest,
                    "passed": technical[check_id].passed,
                }
                for check_id in sorted(technical)
            ],
            "terms_digest": evidence.terms_digest,
            "universe_version": evidence.universe_version,
        },
        "specification": {
            "calendar_version": specification.calendar_version,
            "corporate_action_version": specification.corporate_action_version,
            "frozen_at": _timestamp(specification.frozen_at),
            "identifier_authority": specification.identifier_authority,
            "required_checks": sorted(specification.required_checks),
            "source_id": specification.source_id,
            "specification_id": specification.specification_id,
            "universe_version": specification.universe_version,
        },
    }


def evaluate_admission(
    specification: AdmissionSpecification,
    evidence: AdmissionEvidence,
) -> AdmissionReport:
    """Evaluate one complete evidence set without I/O or ambient time.

    Invalid technical evidence raises :class:`AdmissionEvidenceError`; it cannot
    be converted into a report that appears to have evaluated every required
    check.
    """

    technical = _validate_technical_evidence(specification, evidence)
    _validate_temporal_evidence(specification, evidence, technical)
    checks: list[AdmissionCheck] = []

    source_matches = evidence.source_id == specification.source_id
    checks.append(
        _gate(
            "source_id",
            source_matches,
            f"Evidence is bound to the required source {specification.source_id!r}.",
            f"Expected source {specification.source_id!r}; observed {evidence.source_id!r}.",
        )
    )
    vendor_source = evidence.source_kind is SourceKind.VENDOR
    checks.append(
        _gate(
            "source_kind",
            vendor_source,
            "Source is an external vendor.",
            "Synthetic and recorded fixtures are never eligible for admission.",
        )
    )
    checks.append(
        _gate(
            "licensed",
            evidence.licensed,
            "Source is explicitly licensed.",
            "Source has no active licensed-data assertion.",
        )
    )
    entitlement_active = evidence.entitlement_status is EntitlementStatus.ACTIVE
    checks.append(
        _gate(
            "entitlement",
            entitlement_active,
            "Feed entitlement is active.",
            f"Feed entitlement is {evidence.entitlement_status.value}.",
        )
    )
    terms_present = evidence.terms_digest is not None
    checks.append(
        _gate(
            "terms_digest",
            terms_present,
            "Entitlement terms have a valid SHA-256 digest.",
            "Entitlement terms digest is absent.",
            evidence_digest=evidence.terms_digest,
        )
    )

    frozen_values = (
        (
            "identifier_authority",
            evidence.identifier_authority,
            specification.identifier_authority,
        ),
        ("universe_version", evidence.universe_version, specification.universe_version),
        ("calendar_version", evidence.calendar_version, specification.calendar_version),
        (
            "corporate_action_version",
            evidence.corporate_action_version,
            specification.corporate_action_version,
        ),
    )
    frozen_values_match = True
    for check_id, observed, expected in frozen_values:
        matches = observed == expected
        frozen_values_match = frozen_values_match and matches
        checks.append(
            _gate(
                check_id,
                matches,
                f"Evidence pins the required value {expected!r}.",
                f"Expected {expected!r}; observed {observed!r}.",
            )
        )

    technical_failed = False
    for check_id in sorted(technical):
        result = technical[check_id]
        technical_failed = technical_failed or not result.passed
        checks.append(
            _gate(
                f"technical:{check_id}",
                result.passed,
                "Required technical check passed.",
                "Required technical check failed.",
                evidence_digest=result.evidence_digest,
            )
        )

    approval = evidence.approval
    independent = approval is not None and approval.reviewer_id != evidence.executor_id
    approved = (
        approval is not None and independent and approval.decision is ApprovalDecision.APPROVED
    )
    approval_rejected = (
        approval is not None and independent and approval.decision is ApprovalDecision.REJECTED
    )
    if approval is None:
        approval_check = AdmissionCheck(
            check_id="independent_approval",
            status=AdmissionCheckStatus.PENDING,
            detail="Independent approval has not been recorded.",
        )
    elif not independent:
        approval_check = AdmissionCheck(
            check_id="independent_approval",
            status=AdmissionCheckStatus.PENDING,
            detail="Reviewer must differ from the admission executor.",
        )
    else:
        approval_check = _gate(
            "independent_approval",
            approval.decision is ApprovalDecision.APPROVED,
            "An independent reviewer approved this evidence.",
            "An independent reviewer rejected this evidence.",
        )
    checks.append(approval_check)

    blocked = not (
        source_matches
        and vendor_source
        and evidence.licensed
        and entitlement_active
        and terms_present
        and frozen_values_match
    )
    if blocked:
        status = AdmissionStatus.BLOCKED
    elif technical_failed or approval_rejected:
        status = AdmissionStatus.REJECTED
    elif not approved:
        status = AdmissionStatus.REVIEW_PENDING
    else:
        status = AdmissionStatus.ADMITTED

    canonical_input = _canonical_input(specification, evidence, technical)
    evidence_digest = _digest(canonical_input)
    run_id = f"admission-{evidence_digest[:32]}"
    report_material = {
        "checks": [
            {
                "check_id": check.check_id,
                "detail": check.detail,
                "evidence_digest": check.evidence_digest,
                "status": check.status.value,
            }
            for check in checks
        ],
        "evaluated_at": _timestamp(evidence.evaluated_at),
        "evidence_digest": evidence_digest,
        "run_id": run_id,
        "source_id": evidence.source_id,
        "specification_id": specification.specification_id,
        "status": status.value,
    }
    return AdmissionReport(
        run_id=run_id,
        evidence_digest=evidence_digest,
        report_digest=_digest(report_material),
        specification_id=specification.specification_id,
        source_id=evidence.source_id,
        status=status,
        evaluated_at=evidence.evaluated_at,
        checks=tuple(checks),
    )
