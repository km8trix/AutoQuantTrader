"""Authoritative exposure-derived inputs for the Phase 5B moderate policy.

The producer joins one attested account snapshot, the complete active-capacity
universe observed under the same account lock, an optional proposed buy
exposure projection, and the exact coordinator fence.  It performs no policy
assignment, admission, reservation, control transition, or broker I/O.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from packages.domain.advanced_risk import (
    AdvancedRiskEvidenceSource,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_policy import (
    ADVANCED_RISK_POLICY_CONTRACT_VERSION,
    MODERATE_ADVANCED_RISK_ENVIRONMENT,
    MODERATE_ADVANCED_RISK_INSTRUMENTS,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    MODERATE_ADVANCED_RISK_RULES,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskRule,
    ModerateAdvancedRiskRuleId,
    advanced_risk_policy_source_set_sha256,
    conservative_positive_risk_decimal,
)
from packages.domain.batch_risk import (
    ActiveCapacityUniverse,
    BatchRiskError,
    BatchRiskLimits,
    VersionedBatchRiskSnapshot,
    batch_risk_reservation_terms,
    validate_batch_risk_evidence,
)
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import (
    DECIMAL_ARITHMETIC_VERSION,
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_sum,
)
from packages.domain.models import OrderIntentBatch, Side, TargetPortfolio
from packages.domain.risk import intent_payload_hash

ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION = "phase5b-advanced-risk-exposure-source-v1"
MAX_ADVANCED_RISK_FENCE_TOKEN = (1 << 63) - 1

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INSTRUMENT_SYMBOLS = {
    "US-ETF-DIA": "DIA",
    "US-ETF-IWM": "IWM",
    "US-ETF-QQQ": "QQQ",
    "US-ETF-SPY": "SPY",
}
_EXPOSURE_RULE_IDS = {
    ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
    ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
    ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
    ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
}
_RULE_BY_ID = {rule.rule_id: rule for rule in MODERATE_ADVANCED_RISK_RULES}


class AdvancedRiskExposureSourceError(ValueError):
    """Exposure source facts are malformed or cannot be joined causally."""


class AdvancedRiskExposureSourceConflict(AdvancedRiskExposureSourceError):
    """Supposedly joint immutable exposure facts conflict."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256 = _sha256(
    (
        ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
        "proposed_batch_buy_exposure_authority",
        "phase2_reservation_terms_after_exact_batch_derivation",
        "buy_members_only",
        "market_price_buffer_included",
        "fees_excluded_from_security_exposure",
        "sell_members_retained_only_by_the_bound_batch_digest",
    )
)


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskExposureSourceError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskExposureSourceError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskExposureSourceError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AdvancedRiskExposureSourceError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise AdvancedRiskExposureSourceError(f"{field_name} must be UTC")


def _persisted_decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise AdvancedRiskExposureSourceError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise AdvancedRiskExposureSourceError(str(error)) from error


@dataclass(frozen=True, slots=True)
class ProposedBatchBuyExposure:
    """One exact proposed BUY member produced by Phase 2 reservation terms."""

    intent_id: str
    intent_sha256: str
    instrument_id: str
    exposure: Decimal

    def __post_init__(self) -> None:
        _require_text(self.intent_id, "proposed exposure intent ID")
        _require_sha256(self.intent_sha256, "proposed exposure intent_sha256")
        if self.instrument_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS:
            raise AdvancedRiskExposureSourceError(
                "proposed exposure instrument is outside the moderate policy"
            )
        exposure = _persisted_decimal(self.exposure, "proposed buy exposure")
        if exposure <= 0:
            raise AdvancedRiskExposureSourceError("proposed buy exposure must be positive")
        object.__setattr__(self, "exposure", exposure)

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
                "proposed_buy_exposure",
                self.intent_id,
                self.intent_sha256,
                self.instrument_id,
                self.exposure,
            )
        )


@dataclass(frozen=True, slots=True)
class ProposedBatchBuyExposureSet:
    """Authority-bound BUY projection for one complete proposed intent batch."""

    intent_batch_id: str
    intent_batch_sha256: str
    snapshot_sha256: str
    exposure_authority_sha256: str
    members: tuple[ProposedBatchBuyExposure, ...]

    def __post_init__(self) -> None:
        _require_text(self.intent_batch_id, "proposed exposure batch ID")
        for value, field_name in (
            (self.intent_batch_sha256, "proposed exposure batch_sha256"),
            (self.snapshot_sha256, "proposed exposure snapshot_sha256"),
            (
                self.exposure_authority_sha256,
                "proposed exposure authority_sha256",
            ),
        ):
            _require_sha256(value, field_name)
        if self.exposure_authority_sha256 != PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256:
            raise AdvancedRiskExposureSourceError(
                "proposed exposure does not use the approved derivation authority"
            )
        if type(self.members) is not tuple or any(
            type(member) is not ProposedBatchBuyExposure for member in self.members
        ):
            raise AdvancedRiskExposureSourceError(
                "proposed exposure members must be an exact tuple"
            )
        for member in self.members:
            member.__post_init__()
        expected = tuple(
            sorted(
                self.members,
                key=lambda member: (member.instrument_id, member.intent_id),
            )
        )
        if self.members != expected:
            raise AdvancedRiskExposureSourceError(
                "proposed exposure members must be canonically ordered"
            )
        intent_ids = tuple(member.intent_id for member in self.members)
        if len(intent_ids) != len(set(intent_ids)):
            raise AdvancedRiskExposureSourceConflict("proposed exposure repeats an intent")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
                "proposed_buy_exposure_set",
                self.intent_batch_id,
                self.intent_batch_sha256,
                self.snapshot_sha256,
                self.exposure_authority_sha256,
                tuple(member.semantic_sha256 for member in self.members),
            )
        )


def proposed_batch_buy_exposure_from_phase2(
    *,
    batch: OrderIntentBatch,
    target: TargetPortfolio,
    snapshot: VersionedBatchRiskSnapshot,
    limits: BatchRiskLimits,
    evaluated_at: datetime,
) -> ProposedBatchBuyExposureSet:
    """Project BUY exposure with the exact validation and terms used by Phase 2."""

    if type(batch) is not OrderIntentBatch:
        raise AdvancedRiskExposureSourceError(
            "proposed exposure requires an exact OrderIntentBatch"
        )
    if type(target) is not TargetPortfolio:
        raise AdvancedRiskExposureSourceError("proposed exposure requires an exact TargetPortfolio")
    if type(snapshot) is not VersionedBatchRiskSnapshot:
        raise AdvancedRiskExposureSourceError(
            "proposed exposure requires an exact VersionedBatchRiskSnapshot"
        )
    if type(limits) is not BatchRiskLimits:
        raise AdvancedRiskExposureSourceError("proposed exposure requires exact Phase 2 limits")
    _require_utc(evaluated_at, "proposed exposure evaluated_at")
    try:
        validate_batch_risk_evidence(
            batch,
            target,
            snapshot,
            evaluated_at,
        )
        members = tuple(
            sorted(
                (
                    ProposedBatchBuyExposure(
                        intent_id=intent.intent_id,
                        intent_sha256=intent_payload_hash(intent),
                        instrument_id=intent.instrument_id,
                        exposure=batch_risk_reservation_terms(
                            intent,
                            limits,
                        ).reserved_buy_exposure,
                    )
                    for intent in batch.intents
                    if intent.side is Side.BUY
                ),
                key=lambda member: (member.instrument_id, member.intent_id),
            )
        )
    except (BatchRiskError, ValueError) as error:
        raise AdvancedRiskExposureSourceError(
            "proposed exposure failed exact Phase 2 derivation"
        ) from error
    return ProposedBatchBuyExposureSet(
        intent_batch_id=batch.intent_batch_id,
        intent_batch_sha256=batch.semantic_sha256,
        snapshot_sha256=snapshot.semantic_sha256,
        exposure_authority_sha256=PROPOSED_BATCH_BUY_EXPOSURE_AUTHORITY_SHA256,
        members=members,
    )


@dataclass(frozen=True, slots=True)
class AdvancedRiskExposureWatermark:
    """Exact joint snapshot/capacity/batch/fence source boundary."""

    account_id: str
    environment: str
    snapshot_version: str
    snapshot_sha256: str
    account_projection_sha256: str
    settlement_projection_sha256: str
    snapshot_as_of: datetime
    active_capacity_sha256: str
    proposed_batch_sha256: str | None
    proposed_exposure_sha256: str | None
    fence_token: int
    fence_sha256: str
    observed_at: datetime
    current_equity: Decimal
    current_gross_exposure: Decimal
    current_net_exposure: Decimal
    snapshot_validation_complete: bool
    integrity_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "exposure watermark account ID", 64),
            (self.environment, "exposure watermark environment", 32),
            (self.snapshot_version, "exposure watermark snapshot version", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        if self.environment != MODERATE_ADVANCED_RISK_ENVIRONMENT:
            raise AdvancedRiskExposureSourceError("moderate exposure watermark is paper-only")
        for value, field_name in (
            (self.snapshot_sha256, "exposure watermark snapshot_sha256"),
            (
                self.account_projection_sha256,
                "exposure watermark account_projection_sha256",
            ),
            (
                self.settlement_projection_sha256,
                "exposure watermark settlement_projection_sha256",
            ),
            (
                self.active_capacity_sha256,
                "exposure watermark active_capacity_sha256",
            ),
            (self.fence_sha256, "exposure watermark fence_sha256"),
        ):
            _require_sha256(value, field_name)
        if (self.proposed_batch_sha256 is None) != (self.proposed_exposure_sha256 is None):
            raise AdvancedRiskExposureSourceError(
                "exposure watermark proposed batch bindings must be all-or-none"
            )
        if self.proposed_batch_sha256 is not None:
            _require_sha256(
                self.proposed_batch_sha256,
                "exposure watermark proposed_batch_sha256",
            )
            assert self.proposed_exposure_sha256 is not None
            _require_sha256(
                self.proposed_exposure_sha256,
                "exposure watermark proposed_exposure_sha256",
            )
        if (
            type(self.fence_token) is not int
            or self.fence_token < 1
            or self.fence_token > MAX_ADVANCED_RISK_FENCE_TOKEN
        ):
            raise AdvancedRiskExposureSourceError("exposure watermark fence token is out of range")
        _require_utc(self.snapshot_as_of, "exposure watermark snapshot_as_of")
        _require_utc(self.observed_at, "exposure watermark observed_at")
        if self.observed_at < self.snapshot_as_of:
            raise AdvancedRiskExposureSourceError("exposure watermark cannot predate its snapshot")
        for field_name in (
            "current_equity",
            "current_gross_exposure",
            "current_net_exposure",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(
                    getattr(self, field_name),
                    f"exposure watermark {field_name}",
                ),
            )
        if type(self.snapshot_validation_complete) is not bool:
            raise AdvancedRiskExposureSourceError("snapshot_validation_complete must be bool")
        if type(self.integrity_reasons) is not tuple:
            raise AdvancedRiskExposureSourceError(
                "exposure integrity reasons must be an exact tuple"
            )
        for reason in self.integrity_reasons:
            _require_text(reason, "exposure integrity reason")
        has_validation_failure = "snapshot_validation_failed" in self.integrity_reasons
        if (
            self.integrity_reasons != tuple(sorted(set(self.integrity_reasons)))
            or has_validation_failure is self.snapshot_validation_complete
        ):
            raise AdvancedRiskExposureSourceError(
                "exposure integrity reasons must be canonical and consistent"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
                ADVANCED_RISK_POLICY_CONTRACT_VERSION,
                MODERATE_ADVANCED_RISK_POLICY_SHA256,
                DECIMAL_ARITHMETIC_VERSION,
                "exposure_watermark",
                self.account_id,
                self.environment,
                self.snapshot_version,
                self.snapshot_sha256,
                self.account_projection_sha256,
                self.settlement_projection_sha256,
                self.snapshot_as_of,
                self.active_capacity_sha256,
                self.proposed_batch_sha256,
                self.proposed_exposure_sha256,
                self.fence_token,
                self.fence_sha256,
                self.observed_at,
                self.current_equity,
                self.current_gross_exposure,
                self.current_net_exposure,
                self.snapshot_validation_complete,
                self.integrity_reasons,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
                "exposure_watermark",
                self.semantic_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class AdvancedRiskExposureDerivation:
    """Auditable numerator/denominator derivation for one emitted observation."""

    account_id: str
    rule_id: ModerateAdvancedRiskRuleId
    subject_id: str
    current_component: Decimal
    active_buy_component: Decimal
    proposed_buy_component: Decimal
    numerator: Decimal
    denominator: Decimal | None
    completeness: AdvancedRiskObservationCompleteness
    value: Decimal | None
    incomplete_reason: str | None
    source_set_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "exposure derivation account ID", maximum=64)
        if (
            type(self.rule_id) is not ModerateAdvancedRiskRuleId
            or self.rule_id not in _EXPOSURE_RULE_IDS
        ):
            raise AdvancedRiskExposureSourceError("exposure derivation rule is unsupported")
        _require_text(self.subject_id, "exposure derivation subject ID")
        for field_name in (
            "current_component",
            "active_buy_component",
            "proposed_buy_component",
            "numerator",
        ):
            object.__setattr__(
                self,
                field_name,
                _persisted_decimal(
                    getattr(self, field_name),
                    f"exposure derivation {field_name}",
                ),
            )
        if self.active_buy_component < 0 or self.proposed_buy_component < 0:
            raise AdvancedRiskExposureSourceError(
                "exposure derivation pending buy components must be non-negative"
            )
        if self.numerator < 0:
            raise AdvancedRiskExposureSourceError(
                "exposure derivation numerator must be non-negative"
            )
        if (
            self.current_component < 0
            and self.rule_id is not ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE
        ):
            raise AdvancedRiskExposureSourceError(
                "exposure derivation current component must be non-negative"
            )
        if self.denominator is not None:
            object.__setattr__(
                self,
                "denominator",
                _persisted_decimal(
                    self.denominator,
                    "exposure derivation denominator",
                ),
            )
        if type(self.completeness) is not AdvancedRiskObservationCompleteness:
            raise AdvancedRiskExposureSourceError("exposure derivation completeness is unsupported")
        if self.completeness is AdvancedRiskObservationCompleteness.COMPLETE:
            if self.value is None or self.incomplete_reason is not None:
                raise AdvancedRiskExposureSourceError(
                    "complete exposure derivation requires only an exact value"
                )
            object.__setattr__(
                self,
                "value",
                _persisted_decimal(self.value, "exposure derivation value"),
            )
        else:
            if self.value is not None:
                raise AdvancedRiskExposureSourceError(
                    "incomplete exposure derivation cannot carry a value"
                )
            _require_text(
                self.incomplete_reason or "",
                "exposure derivation incomplete reason",
                maximum=512,
            )
        if self.rule_id is ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY:
            if self.denominator is not None or self.value not in {
                Decimal(0),
                Decimal(1),
            }:
                raise AdvancedRiskExposureSourceError(
                    "cash-integrity derivation must be binary without a denominator"
                )
            if self.numerator != self.value:
                raise AdvancedRiskExposureSourceError(
                    "cash-integrity numerator must equal its binary value"
                )
        else:
            if self.denominator is None:
                raise AdvancedRiskExposureSourceError(
                    "ratio exposure derivation requires an exact denominator"
                )
            if (
                self.completeness is AdvancedRiskObservationCompleteness.COMPLETE
                and self.denominator <= 0
            ):
                raise AdvancedRiskExposureSourceError(
                    "complete ratio derivation requires a positive denominator"
                )
            if self.value is not None and self.value < 0:
                raise AdvancedRiskExposureSourceError(
                    "ratio exposure derivation value must be non-negative"
                )
        _require_sha256(self.source_set_sha256, "exposure derivation source_set_sha256")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "exposure_derivation",
            self.account_id,
            self.rule_id,
            self.subject_id,
            self.current_component,
            self.active_buy_component,
            self.proposed_buy_component,
            self.numerator,
            self.denominator,
            self.completeness,
            self.value,
            self.incomplete_reason,
            self.source_set_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskExposureEvidence:
    """Complete seven-observation exposure source result."""

    watermark: AdvancedRiskExposureWatermark
    derivations: tuple[AdvancedRiskExposureDerivation, ...]
    observations: tuple[AdvancedRiskPolicyObservation, ...]

    def __post_init__(self) -> None:
        if type(self.watermark) is not AdvancedRiskExposureWatermark:
            raise AdvancedRiskExposureSourceError("exposure evidence watermark must be exact")
        self.watermark.__post_init__()
        if type(self.derivations) is not tuple or any(
            type(item) is not AdvancedRiskExposureDerivation for item in self.derivations
        ):
            raise AdvancedRiskExposureSourceError("exposure evidence derivations must be exact")
        if type(self.observations) is not tuple or any(
            type(item) is not AdvancedRiskPolicyObservation for item in self.observations
        ):
            raise AdvancedRiskExposureSourceError("exposure evidence observations must be exact")
        for derivation in self.derivations:
            derivation.__post_init__()
        for observation in self.observations:
            observation.__post_init__()
        derivation_keys = tuple((item.rule_id, item.subject_id) for item in self.derivations)
        observation_keys = tuple((item.rule_id, item.subject_id) for item in self.observations)
        expected_keys = tuple(
            sorted(
                (
                    *(
                        (
                            ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
                            instrument_id,
                        )
                        for instrument_id in MODERATE_ADVANCED_RISK_INSTRUMENTS
                    ),
                    (
                        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
                        self.watermark.account_id,
                    ),
                    (
                        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
                        self.watermark.account_id,
                    ),
                    (
                        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
                        self.watermark.account_id,
                    ),
                ),
                key=lambda item: (item[0].value, item[1]),
            )
        )
        if derivation_keys != expected_keys or observation_keys != expected_keys:
            raise AdvancedRiskExposureSourceConflict(
                "exposure evidence requires exact canonical rule coverage"
            )
        for derivation, observation in zip(
            self.derivations,
            self.observations,
            strict=True,
        ):
            if (
                observation.account_id != self.watermark.account_id
                or observation.environment != self.watermark.environment
                or observation.rule_id is not derivation.rule_id
                or observation.subject_id != derivation.subject_id
                or observation.completeness is not derivation.completeness
                or observation.value != derivation.value
                or observation.source_set_sha256 != derivation.source_set_sha256
                or observation.evidence_sha256 != derivation.semantic_sha256
            ):
                raise AdvancedRiskExposureSourceConflict(
                    "exposure observation does not bind its exact derivation"
                )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_EXPOSURE_SOURCE_CONTRACT_VERSION,
                "exposure_evidence",
                self.watermark.semantic_sha256,
                tuple(item.semantic_sha256 for item in self.derivations),
                tuple(item.semantic_sha256 for item in self.observations),
            )
        )

    @property
    def source_members(self) -> tuple[AdvancedRiskEvidenceSource, ...]:
        """Return the exact retained membership that authenticates each observation."""

        return (advanced_risk_exposure_source(self.watermark),)


def _rule(rule_id: ModerateAdvancedRiskRuleId) -> ModerateAdvancedRiskRule:
    return _RULE_BY_ID[rule_id]


def _ratio(
    numerator: Decimal,
    denominator: Decimal,
    field_name: str,
) -> Decimal:
    raw = deterministic_decimal_divide(numerator, denominator)
    return conservative_positive_risk_decimal(raw, field_name)


def advanced_risk_exposure_source(
    watermark: AdvancedRiskExposureWatermark,
) -> AdvancedRiskEvidenceSource:
    """Project the joint watermark into its exact durable source reference."""

    if type(watermark) is not AdvancedRiskExposureWatermark:
        raise AdvancedRiskExposureSourceError(
            "advanced-risk exposure source requires an exact watermark"
        )
    watermark.__post_init__()
    return AdvancedRiskEvidenceSource(
        source_kind="advanced_risk_exposure_watermark",
        source_id=watermark.semantic_sha256,
        source_sha256=watermark.semantic_sha256,
        effective_at=watermark.snapshot_as_of,
        available_at=watermark.observed_at,
    )


def _source_set_sha256(watermark: AdvancedRiskExposureWatermark) -> str:
    return advanced_risk_policy_source_set_sha256(
        (advanced_risk_exposure_source(watermark),),
        source_count=1,
    )


def _observation(
    derivation: AdvancedRiskExposureDerivation,
    *,
    watermark: AdvancedRiskExposureWatermark,
    window_started_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    rule = _rule(derivation.rule_id)
    return AdvancedRiskPolicyObservation(
        account_id=watermark.account_id,
        environment=watermark.environment,
        rule_id=derivation.rule_id,
        subject_id=derivation.subject_id,
        completeness=derivation.completeness,
        value=derivation.value,
        sample_count=1,
        qualifying_count=None,
        producer_authority_sha256=rule.producer_authority_sha256,
        source_authority_sha256=rule.source_authority_sha256,
        source_set_sha256=derivation.source_set_sha256,
        evidence_sha256=derivation.semantic_sha256,
        window_started_at=window_started_at,
        window_ended_at=watermark.snapshot_as_of,
        observed_at=watermark.observed_at,
        recorded_at=recorded_at,
        incomplete_reason=derivation.incomplete_reason,
    )


def derive_advanced_risk_exposure_evidence(
    *,
    snapshot: VersionedBatchRiskSnapshot,
    active_capacity: ActiveCapacityUniverse,
    fence_token: int,
    fence_sha256: str,
    observed_at: datetime,
    recorded_at: datetime,
    proposed: ProposedBatchBuyExposureSet | None = None,
) -> AdvancedRiskExposureEvidence:
    """Derive concentration/leverage/integrity evidence from one joint watermark."""

    if type(snapshot) is not VersionedBatchRiskSnapshot:
        raise AdvancedRiskExposureSourceError(
            "exposure evidence requires an exact VersionedBatchRiskSnapshot"
        )
    if type(active_capacity) is not ActiveCapacityUniverse:
        raise AdvancedRiskExposureSourceError(
            "exposure evidence requires an exact ActiveCapacityUniverse"
        )
    active_capacity.__post_init__()
    _require_sha256(fence_sha256, "exposure fence_sha256")
    _require_utc(observed_at, "exposure observed_at")
    _require_utc(recorded_at, "exposure recorded_at")
    if recorded_at < observed_at:
        raise AdvancedRiskExposureSourceError("exposure recording cannot predate observation")
    if active_capacity.account_id != snapshot.account_id:
        raise AdvancedRiskExposureSourceConflict(
            "exposure snapshot and active capacity accounts differ"
        )
    if any(
        reservation.currency != snapshot.currency for reservation in active_capacity.reservations
    ):
        raise AdvancedRiskExposureSourceConflict(
            "exposure snapshot and active capacity currencies differ"
        )
    if snapshot.currency != "USD":
        raise AdvancedRiskExposureSourceError("moderate exposure policy requires USD")

    prices = tuple(snapshot.portfolio_snapshot.prices)
    price_ids = tuple(price.instrument_id for price in prices)
    if price_ids != MODERATE_ADVANCED_RISK_INSTRUMENTS:
        raise AdvancedRiskExposureSourceError(
            "exposure snapshot requires exact canonical DIA/IWM/QQQ/SPY price coverage"
        )
    if any(price.symbol != _INSTRUMENT_SYMBOLS[price.instrument_id] for price in prices):
        raise AdvancedRiskExposureSourceConflict(
            "exposure snapshot instrument symbols conflict with policy scope"
        )
    if not snapshot.session.contains(snapshot.portfolio_snapshot.as_of):
        raise AdvancedRiskExposureSourceError(
            "exposure snapshot must be inside the regular session"
        )
    if not snapshot.session.contains(observed_at):
        raise AdvancedRiskExposureSourceError(
            "exposure observation must be inside the regular session"
        )
    if snapshot.session.opens_at >= snapshot.portfolio_snapshot.as_of:
        raise AdvancedRiskExposureSourceError(
            "exposure snapshot requires a non-empty regular-session causal window"
        )
    if any(
        authorization.instrument_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS
        for authorization in active_capacity.authorizations
    ):
        raise AdvancedRiskExposureSourceError(
            "active exposure contains an instrument outside the moderate policy"
        )

    snapshot_sha256 = snapshot.semantic_sha256
    if proposed is not None:
        if type(proposed) is not ProposedBatchBuyExposureSet:
            raise AdvancedRiskExposureSourceError(
                "proposed exposure must be an exact ProposedBatchBuyExposureSet"
            )
        proposed.__post_init__()
        if proposed.snapshot_sha256 != snapshot_sha256:
            raise AdvancedRiskExposureSourceConflict(
                "proposed exposure binds a different risk snapshot"
            )
        active_intent_ids = {
            authorization.intent_id for authorization in active_capacity.authorizations
        }
        proposed_intent_ids = {member.intent_id for member in proposed.members}
        if active_intent_ids & proposed_intent_ids:
            raise AdvancedRiskExposureSourceConflict(
                "proposed exposure duplicates already-active intent capacity"
            )

    raw_positions = tuple(snapshot.account_projection.positions)
    integrity_reasons: set[str] = set()
    if snapshot.account_projection.equity <= 0:
        integrity_reasons.add("nonpositive_equity")
    if any(position.quantity < 0 for position in raw_positions):
        integrity_reasons.add("negative_position")
    if (
        snapshot.account_projection.gross_exposure
        != snapshot.account_projection.net_exposure.copy_abs()
    ):
        integrity_reasons.add("gross_abs_net_mismatch")
    snapshot_validation_complete = True
    try:
        snapshot._validate()
    except (BatchRiskError, ValueError):
        snapshot_validation_complete = False
        integrity_reasons.add("snapshot_validation_failed")

    active_by_instrument = {
        instrument_id: exact_decimal_sum(
            authorization.remaining_buy_exposure
            for authorization in active_capacity.authorizations
            if (authorization.side is Side.BUY and authorization.instrument_id == instrument_id)
        )
        for instrument_id in MODERATE_ADVANCED_RISK_INSTRUMENTS
    }
    proposed_by_instrument = {
        instrument_id: exact_decimal_sum(
            member.exposure
            for member in (() if proposed is None else proposed.members)
            if member.instrument_id == instrument_id
        )
        for instrument_id in MODERATE_ADVANCED_RISK_INSTRUMENTS
    }
    current_by_instrument = {
        instrument_id: exact_decimal_sum(
            (position.market_value if position.market_value > 0 else Decimal(0))
            for position in raw_positions
            if position.instrument_id == instrument_id
        )
        for instrument_id in MODERATE_ADVANCED_RISK_INSTRUMENTS
    }
    active_total = exact_decimal_sum(active_by_instrument.values())
    proposed_total = exact_decimal_sum(proposed_by_instrument.values())
    pending_total = exact_decimal_add(active_total, proposed_total)
    projected_gross = exact_decimal_add(
        snapshot.account_projection.gross_exposure,
        pending_total,
    )
    projected_signed_net = exact_decimal_add(
        snapshot.account_projection.net_exposure,
        pending_total,
    )
    projected_abs_net = projected_signed_net.copy_abs()
    if projected_gross != projected_abs_net:
        integrity_reasons.add("gross_abs_net_mismatch")

    canonical_reasons = tuple(sorted(integrity_reasons))
    watermark = AdvancedRiskExposureWatermark(
        account_id=snapshot.account_id,
        environment=MODERATE_ADVANCED_RISK_ENVIRONMENT,
        snapshot_version=snapshot.version,
        snapshot_sha256=snapshot_sha256,
        account_projection_sha256=snapshot.account_projection.semantic_sha256,
        settlement_projection_sha256=snapshot.settlement_projection.semantic_sha256,
        snapshot_as_of=snapshot.portfolio_snapshot.as_of,
        active_capacity_sha256=active_capacity.semantic_sha256,
        proposed_batch_sha256=(None if proposed is None else proposed.intent_batch_sha256),
        proposed_exposure_sha256=(None if proposed is None else proposed.semantic_sha256),
        fence_token=fence_token,
        fence_sha256=fence_sha256,
        observed_at=observed_at,
        current_equity=snapshot.account_projection.equity,
        current_gross_exposure=snapshot.account_projection.gross_exposure,
        current_net_exposure=snapshot.account_projection.net_exposure,
        snapshot_validation_complete=snapshot_validation_complete,
        integrity_reasons=canonical_reasons,
    )
    source_set_sha256 = _source_set_sha256(watermark)
    ratios_complete = not canonical_reasons
    incomplete_reason = (
        None if ratios_complete else "cash-account integrity prevents a numeric exposure ratio"
    )
    ratio_completeness = (
        AdvancedRiskObservationCompleteness.COMPLETE
        if ratios_complete
        else AdvancedRiskObservationCompleteness.UNAVAILABLE
    )
    equity = snapshot.account_projection.equity

    derivations: list[AdvancedRiskExposureDerivation] = []
    for instrument_id in MODERATE_ADVANCED_RISK_INSTRUMENTS:
        numerator = exact_decimal_add(
            current_by_instrument[instrument_id],
            exact_decimal_add(
                active_by_instrument[instrument_id],
                proposed_by_instrument[instrument_id],
            ),
        )
        derivations.append(
            AdvancedRiskExposureDerivation(
                account_id=snapshot.account_id,
                rule_id=ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
                subject_id=instrument_id,
                current_component=current_by_instrument[instrument_id],
                active_buy_component=active_by_instrument[instrument_id],
                proposed_buy_component=proposed_by_instrument[instrument_id],
                numerator=numerator,
                denominator=equity,
                completeness=ratio_completeness,
                value=(
                    _ratio(numerator, equity, "instrument concentration ratio")
                    if ratios_complete
                    else None
                ),
                incomplete_reason=incomplete_reason,
                source_set_sha256=source_set_sha256,
            )
        )

    derivations.extend(
        (
            AdvancedRiskExposureDerivation(
                account_id=snapshot.account_id,
                rule_id=ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
                subject_id=snapshot.account_id,
                current_component=snapshot.account_projection.gross_exposure,
                active_buy_component=active_total,
                proposed_buy_component=proposed_total,
                numerator=projected_gross,
                denominator=equity,
                completeness=ratio_completeness,
                value=(
                    _ratio(projected_gross, equity, "gross leverage multiple")
                    if ratios_complete
                    else None
                ),
                incomplete_reason=incomplete_reason,
                source_set_sha256=source_set_sha256,
            ),
            AdvancedRiskExposureDerivation(
                account_id=snapshot.account_id,
                rule_id=ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
                subject_id=snapshot.account_id,
                current_component=snapshot.account_projection.net_exposure,
                active_buy_component=active_total,
                proposed_buy_component=proposed_total,
                numerator=projected_abs_net,
                denominator=equity,
                completeness=ratio_completeness,
                value=(
                    _ratio(projected_abs_net, equity, "absolute net leverage multiple")
                    if ratios_complete
                    else None
                ),
                incomplete_reason=incomplete_reason,
                source_set_sha256=source_set_sha256,
            ),
            AdvancedRiskExposureDerivation(
                account_id=snapshot.account_id,
                rule_id=ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
                subject_id=snapshot.account_id,
                current_component=snapshot.account_projection.gross_exposure,
                active_buy_component=active_total,
                proposed_buy_component=proposed_total,
                numerator=Decimal(1) if canonical_reasons else Decimal(0),
                denominator=None,
                completeness=AdvancedRiskObservationCompleteness.COMPLETE,
                value=Decimal(1) if canonical_reasons else Decimal(0),
                incomplete_reason=None,
                source_set_sha256=source_set_sha256,
            ),
        )
    )
    ordered_derivations = tuple(
        sorted(
            derivations,
            key=lambda item: (item.rule_id.value, item.subject_id),
        )
    )
    observations = tuple(
        _observation(
            derivation,
            watermark=watermark,
            window_started_at=snapshot.session.opens_at,
            recorded_at=recorded_at,
        )
        for derivation in ordered_derivations
    )
    return AdvancedRiskExposureEvidence(
        watermark=watermark,
        derivations=ordered_derivations,
        observations=observations,
    )
