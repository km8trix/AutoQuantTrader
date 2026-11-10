"""Pure, non-authorizing prerequisite gate for production historical data.

The gate inventories opaque, externally supplied evidence references.  It does
not authenticate an external human or authority, upgrade research evidence,
construct admission evidence, or create a :class:`HistoricalBarSource`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from packages.domain.canonical import canonical_json_text

PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION = "phase1-production-market-data-evidence-gate-v1"

_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProductionMarketDataEvidenceError(ValueError):
    """A prerequisite specification, evidence reference, or review is malformed."""


class ProductionMarketDataEvidenceConflict(ProductionMarketDataEvidenceError):
    """A sealed assessment or canonical evidence collection was altered."""


class ProductionEvidenceRole(StrEnum):
    """Fixed production evidence dimensions required before source implementation."""

    IDENTITY_LIFECYCLE = "production_identity_lifecycle"
    CALENDAR = "production_calendar"
    CORPORATE_ACTIONS = "production_corporate_action_authority"
    RAW_PRICE_PROVENANCE = "genuine_raw_price_and_market_provenance"
    LICENSE_RIGHTS = "production_license_rights_and_entitlement"


REQUIRED_PRODUCTION_EVIDENCE_ROLES = tuple(ProductionEvidenceRole)


class ProductionEvidenceClass(StrEnum):
    """Provenance classification asserted by an injected evidence reference."""

    EXTERNAL_AUTHORITY = "external_authority"
    SYNTHETIC_CONTRACT = "synthetic_contract"
    RESEARCH_CAPTURE = "research_capture"
    CONTRACT_ONLY = "contract_only"
    RECORDED_FIXTURE = "recorded_fixture"


class ProductionEvidenceDecision(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"


class ProductionReviewDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ProductionEvidenceGateStatus(StrEnum):
    BLOCKED = "blocked"
    READY_FOR_ADMISSION_EVALUATION = "ready_for_admission_evaluation"


class ProductionAuthorityEffect(StrEnum):
    NONE = "none"


class ProductionEvidenceBlocker(StrEnum):
    """Canonical fail-closed reasons the evidence inventory is incomplete."""

    IDENTITY_LIFECYCLE_EVIDENCE_MISSING = "identity_lifecycle_evidence_missing"
    CALENDAR_EVIDENCE_MISSING = "calendar_evidence_missing"
    CORPORATE_ACTION_EVIDENCE_MISSING = "corporate_action_evidence_missing"
    RAW_PRICE_PROVENANCE_EVIDENCE_MISSING = "raw_price_provenance_evidence_missing"
    LICENSE_RIGHTS_EVIDENCE_MISSING = "license_rights_evidence_missing"
    DUPLICATE_EVIDENCE_ROLE = "duplicate_evidence_role"
    NON_PRODUCTION_EVIDENCE = "non_production_evidence"
    EVIDENCE_REJECTED = "evidence_rejected"
    SOURCE_BINDING_MISMATCH = "source_binding_mismatch"
    PROVIDER_BINDING_MISMATCH = "provider_binding_mismatch"
    DATASET_BINDING_MISMATCH = "dataset_binding_mismatch"
    FEED_BINDING_MISMATCH = "feed_binding_mismatch"
    PROFILE_BINDING_MISMATCH = "profile_binding_mismatch"
    SCOPE_BINDING_MISMATCH = "scope_binding_mismatch"
    EVIDENCE_PREDATES_SPECIFICATION = "evidence_predates_specification"
    EVIDENCE_OBSERVED_IN_FUTURE = "evidence_observed_in_future"
    EVIDENCE_STALE = "evidence_stale"
    EVALUATION_PREDATES_SPECIFICATION = "evaluation_predates_specification"
    INDEPENDENT_REVIEW_MISSING = "independent_review_missing"
    NON_PRODUCTION_REVIEW = "non_production_review"
    REVIEW_BINDING_MISMATCH = "review_binding_mismatch"
    REVIEW_BUNDLE_MISMATCH = "review_bundle_mismatch"
    REVIEW_PREDATES_EVIDENCE = "review_predates_evidence"
    REVIEW_OBSERVED_IN_FUTURE = "review_observed_in_future"
    REVIEW_STALE = "review_stale"
    SELF_APPROVED = "self_approved"
    REVIEW_REJECTED = "review_rejected"


_BLOCKER_ORDER = {blocker: index for index, blocker in enumerate(ProductionEvidenceBlocker)}
_MISSING_BLOCKER = {
    ProductionEvidenceRole.IDENTITY_LIFECYCLE: (
        ProductionEvidenceBlocker.IDENTITY_LIFECYCLE_EVIDENCE_MISSING
    ),
    ProductionEvidenceRole.CALENDAR: ProductionEvidenceBlocker.CALENDAR_EVIDENCE_MISSING,
    ProductionEvidenceRole.CORPORATE_ACTIONS: (
        ProductionEvidenceBlocker.CORPORATE_ACTION_EVIDENCE_MISSING
    ),
    ProductionEvidenceRole.RAW_PRICE_PROVENANCE: (
        ProductionEvidenceBlocker.RAW_PRICE_PROVENANCE_EVIDENCE_MISSING
    ),
    ProductionEvidenceRole.LICENSE_RIGHTS: (
        ProductionEvidenceBlocker.LICENSE_RIGHTS_EVIDENCE_MISSING
    ),
}


def _require_safe_text(value: str, field_name: str) -> None:
    if type(value) is not str or _SAFE_TEXT.fullmatch(value) is None:
        raise ProductionMarketDataEvidenceError(
            f"{field_name} must contain 1-256 bounded safe characters"
        )


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise ProductionMarketDataEvidenceError(
            f"{field_name} must be a nonzero lowercase SHA-256 digest"
        )


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ProductionMarketDataEvidenceError(
            f"{field_name} must be an exact timezone-aware datetime"
        )
    if value.utcoffset() != timedelta(0):
        raise ProductionMarketDataEvidenceError(f"{field_name} must be stored in UTC")


def _require_exact_enum(value: object, enum_type: type[StrEnum], field_name: str) -> None:
    if type(value) is not enum_type:
        raise ProductionMarketDataEvidenceError(
            f"{field_name} must be an exact {enum_type.__name__}"
        )


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProductionHistoricalSourceEvidenceSpecification:
    """Frozen external-evidence bindings for one proposed historical source."""

    specification_id: str
    source_id: str
    provider: str
    dataset: str
    feed: str
    profile_sha256: str
    scope_sha256: str
    frozen_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.specification_id, "production evidence specification_id"),
            (self.source_id, "production evidence source_id"),
            (self.provider, "production evidence provider"),
            (self.dataset, "production evidence dataset"),
            (self.feed, "production evidence feed"),
        ):
            _require_safe_text(value, field_name)
        _require_sha256(self.profile_sha256, "production evidence profile_sha256")
        _require_sha256(self.scope_sha256, "production evidence scope_sha256")
        _require_utc(self.frozen_at, "production evidence frozen_at")

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION,
                "specification",
                self.specification_id,
                self.source_id,
                self.provider,
                self.dataset,
                self.feed,
                self.profile_sha256,
                self.scope_sha256,
                self.frozen_at,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProductionEvidenceAttestation:
    """Opaque reference to one production prerequisite; never the evidence itself."""

    role: ProductionEvidenceRole
    evidence_class: ProductionEvidenceClass
    decision: ProductionEvidenceDecision
    evidence_id: str
    producer_id: str
    source_id: str
    provider: str
    dataset: str
    feed: str
    profile_sha256: str
    scope_sha256: str
    artifact_sha256: str
    observed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        _require_exact_enum(self.role, ProductionEvidenceRole, "production evidence role")
        _require_exact_enum(
            self.evidence_class,
            ProductionEvidenceClass,
            "production evidence class",
        )
        _require_exact_enum(
            self.decision,
            ProductionEvidenceDecision,
            "production evidence decision",
        )
        for value, field_name in (
            (self.evidence_id, "production evidence ID"),
            (self.producer_id, "production evidence producer ID"),
            (self.source_id, "production evidence source ID"),
            (self.provider, "production evidence provider"),
            (self.dataset, "production evidence dataset"),
            (self.feed, "production evidence feed"),
        ):
            _require_safe_text(value, field_name)
        _require_sha256(self.profile_sha256, "production evidence profile_sha256")
        _require_sha256(self.scope_sha256, "production evidence scope_sha256")
        _require_sha256(self.artifact_sha256, "production evidence artifact_sha256")
        _require_utc(self.observed_at, "production evidence observed_at")
        _require_utc(self.valid_through, "production evidence valid_through")
        if self.valid_through <= self.observed_at:
            raise ProductionMarketDataEvidenceError(
                "production evidence valid_through must follow observed_at"
            )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION,
                "attestation",
                self.role,
                self.evidence_class,
                self.decision,
                self.evidence_id,
                self.producer_id,
                self.source_id,
                self.provider,
                self.dataset,
                self.feed,
                self.profile_sha256,
                self.scope_sha256,
                self.artifact_sha256,
                self.observed_at,
                self.valid_through,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProductionEvidenceBundle:
    """Immutable prerequisite references; omissions remain representable blockers."""

    attestations: tuple[ProductionEvidenceAttestation, ...]

    def __post_init__(self) -> None:
        if type(self.attestations) is not tuple or any(
            type(attestation) is not ProductionEvidenceAttestation
            for attestation in self.attestations
        ):
            raise ProductionMarketDataEvidenceError(
                "production evidence attestations must be an exact immutable tuple"
            )

    @property
    def ordered_attestations(self) -> tuple[ProductionEvidenceAttestation, ...]:
        return tuple(
            sorted(
                self.attestations,
                key=lambda attestation: (
                    attestation.role.value,
                    attestation.evidence_id,
                    attestation.semantic_sha256,
                ),
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION,
                "bundle",
                tuple(attestation.semantic_sha256 for attestation in self.ordered_attestations),
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IndependentProductionEvidenceReview:
    """Review of the exact canonical prerequisite bundle, not a source approval."""

    review_id: str
    reviewer_id: str
    evidence_class: ProductionEvidenceClass
    decision: ProductionReviewDecision
    source_id: str
    provider: str
    dataset: str
    feed: str
    profile_sha256: str
    scope_sha256: str
    evidence_bundle_sha256: str
    reviewed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.review_id, "production evidence review ID"),
            (self.reviewer_id, "production evidence reviewer ID"),
            (self.source_id, "production evidence review source ID"),
            (self.provider, "production evidence review provider"),
            (self.dataset, "production evidence review dataset"),
            (self.feed, "production evidence review feed"),
        ):
            _require_safe_text(value, field_name)
        _require_exact_enum(
            self.evidence_class,
            ProductionEvidenceClass,
            "production evidence review class",
        )
        _require_exact_enum(
            self.decision,
            ProductionReviewDecision,
            "production evidence review decision",
        )
        _require_sha256(self.profile_sha256, "production evidence review profile_sha256")
        _require_sha256(self.scope_sha256, "production evidence review scope_sha256")
        _require_sha256(
            self.evidence_bundle_sha256,
            "production evidence review bundle_sha256",
        )
        _require_utc(self.reviewed_at, "production evidence reviewed_at")
        _require_utc(self.valid_through, "production evidence review valid_through")
        if self.valid_through <= self.reviewed_at:
            raise ProductionMarketDataEvidenceError(
                "production evidence review valid_through must follow reviewed_at"
            )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION,
                "independent_review",
                self.review_id,
                self.reviewer_id,
                self.evidence_class,
                self.decision,
                self.source_id,
                self.provider,
                self.dataset,
                self.feed,
                self.profile_sha256,
                self.scope_sha256,
                self.evidence_bundle_sha256,
                self.reviewed_at,
                self.valid_through,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


def _report_material(
    *,
    specification_sha256: str,
    evidence_bundle_sha256: str,
    review_sha256: str | None,
    executor_sha256: str,
    evaluated_at: datetime,
    blockers: tuple[ProductionEvidenceBlocker, ...],
) -> tuple[object, ...]:
    return (
        PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION,
        "assessment",
        specification_sha256,
        evidence_bundle_sha256,
        review_sha256,
        executor_sha256,
        evaluated_at,
        blockers,
    )


@dataclass(frozen=True, slots=True)
class _ProductionEvidenceAssessmentSeal:
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class ProductionEvidenceGateAssessment:
    """Proof-constructed inventory result with permanently absent authority."""

    specification_sha256: str
    evidence_bundle_sha256: str
    review_sha256: str | None
    executor_sha256: str
    evaluated_at: datetime
    blockers: tuple[ProductionEvidenceBlocker, ...]
    _seal: _ProductionEvidenceAssessmentSeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_sha256(
            self.specification_sha256,
            "production evidence assessment specification_sha256",
        )
        _require_sha256(
            self.evidence_bundle_sha256,
            "production evidence assessment bundle_sha256",
        )
        if self.review_sha256 is not None:
            _require_sha256(
                self.review_sha256,
                "production evidence assessment review_sha256",
            )
        _require_sha256(
            self.executor_sha256,
            "production evidence assessment executor_sha256",
        )
        _require_utc(self.evaluated_at, "production evidence assessment evaluated_at")
        if type(self.blockers) is not tuple or any(
            type(blocker) is not ProductionEvidenceBlocker for blocker in self.blockers
        ):
            raise ProductionMarketDataEvidenceError(
                "production evidence assessment blockers must be an exact tuple"
            )
        if len(set(self.blockers)) != len(self.blockers):
            raise ProductionMarketDataEvidenceConflict(
                "production evidence assessment blockers must be unique"
            )
        if self.blockers != tuple(sorted(self.blockers, key=_BLOCKER_ORDER.__getitem__)):
            raise ProductionMarketDataEvidenceConflict(
                "production evidence assessment blockers are not in canonical order"
            )
        if type(self._seal) is not _ProductionEvidenceAssessmentSeal:
            raise ProductionMarketDataEvidenceError(
                "production evidence assessment requires gate construction"
            )
        expected = _sha256(
            _report_material(
                specification_sha256=self.specification_sha256,
                evidence_bundle_sha256=self.evidence_bundle_sha256,
                review_sha256=self.review_sha256,
                executor_sha256=self.executor_sha256,
                evaluated_at=self.evaluated_at,
                blockers=self.blockers,
            )
        )
        if self._seal.payload_sha256 != expected:
            raise ProductionMarketDataEvidenceConflict(
                "production evidence assessment seal is invalid"
            )

    @property
    def status(self) -> ProductionEvidenceGateStatus:
        if self.blockers:
            return ProductionEvidenceGateStatus.BLOCKED
        return ProductionEvidenceGateStatus.READY_FOR_ADMISSION_EVALUATION

    @property
    def ready_for_admission_evaluation(self) -> bool:
        return not self.blockers

    @property
    def report_id(self) -> str:
        return f"production-evidence-{self.semantic_sha256[:32]}"

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            _report_material(
                specification_sha256=self.specification_sha256,
                evidence_bundle_sha256=self.evidence_bundle_sha256,
                review_sha256=self.review_sha256,
                executor_sha256=self.executor_sha256,
                evaluated_at=self.evaluated_at,
                blockers=self.blockers,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return self._seal.payload_sha256

    @property
    def historical_source_effect(self) -> ProductionAuthorityEffect:
        return ProductionAuthorityEffect.NONE

    @property
    def admission_effect(self) -> ProductionAuthorityEffect:
        return ProductionAuthorityEffect.NONE

    @property
    def canonical_market_data_effect(self) -> ProductionAuthorityEffect:
        return ProductionAuthorityEffect.NONE

    @property
    def trading_effect(self) -> ProductionAuthorityEffect:
        return ProductionAuthorityEffect.NONE

    @property
    def historical_source_authorized(self) -> bool:
        return False

    @property
    def admission_authorized(self) -> bool:
        return False

    @property
    def trading_authorized(self) -> bool:
        return False


def assess_production_market_data_evidence(
    *,
    specification: ProductionHistoricalSourceEvidenceSpecification,
    evidence: ProductionEvidenceBundle,
    review: IndependentProductionEvidenceReview | None,
    executor_id: str,
    evaluated_at: datetime,
) -> ProductionEvidenceGateAssessment:
    """Inventory exact prerequisite bindings without granting downstream authority."""

    if type(specification) is not ProductionHistoricalSourceEvidenceSpecification:
        raise ProductionMarketDataEvidenceError(
            "production evidence gate requires an exact specification"
        )
    specification.__post_init__()
    if type(evidence) is not ProductionEvidenceBundle:
        raise ProductionMarketDataEvidenceError(
            "production evidence gate requires an exact evidence bundle"
        )
    evidence.__post_init__()
    for attestation in evidence.attestations:
        attestation.__post_init__()
    if review is not None:
        if type(review) is not IndependentProductionEvidenceReview:
            raise ProductionMarketDataEvidenceError(
                "production evidence gate requires an exact independent review"
            )
        review.__post_init__()
    _require_safe_text(executor_id, "production evidence executor ID")
    _require_utc(evaluated_at, "production evidence evaluated_at")

    blockers: list[ProductionEvidenceBlocker] = []
    grouped: dict[ProductionEvidenceRole, list[ProductionEvidenceAttestation]] = {
        role: [] for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES
    }
    for attestation in evidence.attestations:
        grouped[attestation.role].append(attestation)

    for role in REQUIRED_PRODUCTION_EVIDENCE_ROLES:
        if not grouped[role]:
            blockers.append(_MISSING_BLOCKER[role])
        elif len(grouped[role]) > 1:
            blockers.append(ProductionEvidenceBlocker.DUPLICATE_EVIDENCE_ROLE)

    if evaluated_at < specification.frozen_at:
        blockers.append(ProductionEvidenceBlocker.EVALUATION_PREDATES_SPECIFICATION)

    for attestation in evidence.attestations:
        if attestation.evidence_class is not ProductionEvidenceClass.EXTERNAL_AUTHORITY:
            blockers.append(ProductionEvidenceBlocker.NON_PRODUCTION_EVIDENCE)
        if attestation.decision is not ProductionEvidenceDecision.VERIFIED:
            blockers.append(ProductionEvidenceBlocker.EVIDENCE_REJECTED)
        if attestation.source_id != specification.source_id:
            blockers.append(ProductionEvidenceBlocker.SOURCE_BINDING_MISMATCH)
        if attestation.provider != specification.provider:
            blockers.append(ProductionEvidenceBlocker.PROVIDER_BINDING_MISMATCH)
        if attestation.dataset != specification.dataset:
            blockers.append(ProductionEvidenceBlocker.DATASET_BINDING_MISMATCH)
        if attestation.feed != specification.feed:
            blockers.append(ProductionEvidenceBlocker.FEED_BINDING_MISMATCH)
        if attestation.profile_sha256 != specification.profile_sha256:
            blockers.append(ProductionEvidenceBlocker.PROFILE_BINDING_MISMATCH)
        if attestation.scope_sha256 != specification.scope_sha256:
            blockers.append(ProductionEvidenceBlocker.SCOPE_BINDING_MISMATCH)
        if attestation.observed_at < specification.frozen_at:
            blockers.append(ProductionEvidenceBlocker.EVIDENCE_PREDATES_SPECIFICATION)
        if attestation.observed_at > evaluated_at:
            blockers.append(ProductionEvidenceBlocker.EVIDENCE_OBSERVED_IN_FUTURE)
        if evaluated_at >= attestation.valid_through:
            blockers.append(ProductionEvidenceBlocker.EVIDENCE_STALE)

    if review is None:
        blockers.append(ProductionEvidenceBlocker.INDEPENDENT_REVIEW_MISSING)
        review_sha256 = None
    else:
        review_sha256 = review.semantic_sha256
        if review.evidence_class is not ProductionEvidenceClass.EXTERNAL_AUTHORITY:
            blockers.append(ProductionEvidenceBlocker.NON_PRODUCTION_REVIEW)
        if review.decision is not ProductionReviewDecision.APPROVED:
            blockers.append(ProductionEvidenceBlocker.REVIEW_REJECTED)
        if (
            review.source_id != specification.source_id
            or review.provider != specification.provider
            or review.dataset != specification.dataset
            or review.feed != specification.feed
            or review.profile_sha256 != specification.profile_sha256
            or review.scope_sha256 != specification.scope_sha256
        ):
            blockers.append(ProductionEvidenceBlocker.REVIEW_BINDING_MISMATCH)
        if review.evidence_bundle_sha256 != evidence.semantic_sha256:
            blockers.append(ProductionEvidenceBlocker.REVIEW_BUNDLE_MISMATCH)
        latest_evidence_at = max(
            (attestation.observed_at for attestation in evidence.attestations),
            default=specification.frozen_at,
        )
        if review.reviewed_at < latest_evidence_at:
            blockers.append(ProductionEvidenceBlocker.REVIEW_PREDATES_EVIDENCE)
        if review.reviewed_at > evaluated_at:
            blockers.append(ProductionEvidenceBlocker.REVIEW_OBSERVED_IN_FUTURE)
        if evaluated_at >= review.valid_through:
            blockers.append(ProductionEvidenceBlocker.REVIEW_STALE)
        producers = {attestation.producer_id for attestation in evidence.attestations}
        if review.reviewer_id == executor_id or review.reviewer_id in producers:
            blockers.append(ProductionEvidenceBlocker.SELF_APPROVED)

    ordered_blockers = tuple(sorted(set(blockers), key=_BLOCKER_ORDER.__getitem__))
    executor_sha256 = hashlib.sha256(executor_id.encode("utf-8")).hexdigest()
    material = _report_material(
        specification_sha256=specification.semantic_sha256,
        evidence_bundle_sha256=evidence.semantic_sha256,
        review_sha256=review_sha256,
        executor_sha256=executor_sha256,
        evaluated_at=evaluated_at,
        blockers=ordered_blockers,
    )
    return ProductionEvidenceGateAssessment(
        specification_sha256=specification.semantic_sha256,
        evidence_bundle_sha256=evidence.semantic_sha256,
        review_sha256=review_sha256,
        executor_sha256=executor_sha256,
        evaluated_at=evaluated_at,
        blockers=ordered_blockers,
        _seal=_ProductionEvidenceAssessmentSeal(payload_sha256=_sha256(material)),
    )


__all__ = [
    "PRODUCTION_MARKET_DATA_EVIDENCE_CONTRACT_VERSION",
    "REQUIRED_PRODUCTION_EVIDENCE_ROLES",
    "IndependentProductionEvidenceReview",
    "ProductionAuthorityEffect",
    "ProductionEvidenceAttestation",
    "ProductionEvidenceBlocker",
    "ProductionEvidenceBundle",
    "ProductionEvidenceClass",
    "ProductionEvidenceDecision",
    "ProductionEvidenceGateAssessment",
    "ProductionEvidenceGateStatus",
    "ProductionEvidenceRole",
    "ProductionHistoricalSourceEvidenceSpecification",
    "ProductionMarketDataEvidenceConflict",
    "ProductionMarketDataEvidenceError",
    "ProductionReviewDecision",
    "assess_production_market_data_evidence",
]
