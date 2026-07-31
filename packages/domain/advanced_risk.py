"""Approval-gated, observe-only Phase 5B advanced-risk contracts.

These values describe proposed measurement contracts and structurally complete
measurement evidence.  They do not approve a policy, evaluate a threshold,
authorize execution, reserve capacity, or emit an operational-control command.
Owner-approved metric semantics, limits, actions, activation, persistence, and
atomic BatchRisk composition are deliberately separate future contracts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import DECIMAL_ARITHMETIC_VERSION
from packages.domain.identifiers import canonical_id

ADVANCED_RISK_CONTRACT_VERSION = "phase5b-advanced-risk-observe-only-v1"
MAX_ADVANCED_RISK_RULES = 64
MAX_ADVANCED_RISK_SOURCES = 2_048
MAX_ADVANCED_RISK_SOURCE_COUNT = (1 << 63) - 1

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdvancedRiskError(ValueError):
    """Advanced-risk proposal or observation evidence is malformed."""


class AdvancedRiskFactConflict(AdvancedRiskError):
    """Supposedly immutable advanced-risk evidence conflicts."""


class AdvancedRiskPolicyUnapproved(AdvancedRiskError):
    """A proposed policy was presented where activated policy was required."""


class AdvancedRiskRuleKind(StrEnum):
    """Closed Phase 5 rule families; each still needs approved semantics."""

    SESSION_LOSS = "session_loss"
    SESSION_DRAWDOWN = "session_drawdown"
    CONCENTRATION = "concentration"
    LEVERAGE = "leverage"
    VOLATILITY = "volatility"
    SPREAD = "spread"
    SLIPPAGE = "slippage"
    BROKER_REJECT_RATE = "broker_reject_rate"
    BROKER_RATE_LIMIT = "broker_rate_limit"
    CLOCK_HEALTH = "clock_health"
    DATA_HEALTH = "data_health"
    UNKNOWN_DURATION = "unknown_duration"
    RECONCILIATION_DURATION = "reconciliation_duration"


class AdvancedRiskObservationCompleteness(StrEnum):
    """Evidence completeness without any pass/fail or health implication."""

    COMPLETE = "complete"
    INSUFFICIENT = "insufficient"
    UNAVAILABLE = "unavailable"
    OVERFLOWED = "overflowed"


class AdvancedRiskPolicyReadiness(StrEnum):
    """The only readiness state available before owner activation exists."""

    OWNER_APPROVAL_REQUIRED = "owner_approval_required"


class AdvancedRiskEffect(StrEnum):
    """Explicitly closed authority surface for this observe-only contract."""

    NONE = "none"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: str,
    field_name: str,
    *,
    maximum: int = 128,
) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AdvancedRiskError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise AdvancedRiskError(f"{field_name} must be UTC")


def _persisted_decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise AdvancedRiskError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise AdvancedRiskError(str(error)) from error


def _effect() -> AdvancedRiskEffect:
    return AdvancedRiskEffect.NONE


@dataclass(frozen=True, slots=True)
class AdvancedRiskRuleBinding:
    """One unapproved proposal for how a rule measurement would be produced.

    The calculator and source-schema digests bind proposed artifacts.  They are
    not authenticated source facts and cannot hide a deployable threshold or
    action: this contract has no activation or evaluation operation.
    """

    rule_id: str
    kind: AdvancedRiskRuleKind
    calculator_id: str
    calculator_version: str
    calculator_sha256: str
    source_schema_id: str
    source_schema_version: str
    source_schema_sha256: str
    measurement_scope: str
    measurement_unit: str

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.rule_id, "advanced-risk rule ID", 128),
            (self.calculator_id, "advanced-risk calculator ID", 128),
            (self.calculator_version, "advanced-risk calculator version", 64),
            (self.source_schema_id, "advanced-risk source-schema ID", 128),
            (self.source_schema_version, "advanced-risk source-schema version", 64),
            (self.measurement_scope, "advanced-risk measurement scope", 64),
            (self.measurement_unit, "advanced-risk measurement unit", 64),
        ):
            _require_text(value, field_name, maximum=maximum)
        if type(self.kind) is not AdvancedRiskRuleKind:
            raise AdvancedRiskError("advanced-risk rule kind is unsupported")
        _require_sha256(self.calculator_sha256, "advanced-risk calculator_sha256")
        _require_sha256(
            self.source_schema_sha256,
            "advanced-risk source_schema_sha256",
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "rule_binding",
            self.rule_id,
            self.kind,
            self.calculator_id,
            self.calculator_version,
            self.calculator_sha256,
            self.source_schema_id,
            self.source_schema_version,
            self.source_schema_sha256,
            self.measurement_scope,
            self.measurement_unit,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def trading_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def control_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def activation_effect(self) -> AdvancedRiskEffect:
        return _effect()


@dataclass(frozen=True, slots=True)
class AdvancedRiskPolicyCandidate:
    """A content-addressed proposal that is always explicitly unapproved."""

    policy_id: str
    policy_version: str
    environment: str
    scope_profile_id: str
    scope_profile_sha256: str
    rules: tuple[AdvancedRiskRuleBinding, ...]
    proposed_at: datetime

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.policy_id, "advanced-risk policy ID", 128),
            (self.policy_version, "advanced-risk policy version", 64),
            (self.environment, "advanced-risk environment", 32),
            (self.scope_profile_id, "advanced-risk scope-profile ID", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        _require_sha256(
            self.scope_profile_sha256,
            "advanced-risk scope_profile_sha256",
        )
        _require_utc(self.proposed_at, "advanced-risk proposed_at")
        if type(self.rules) is not tuple or not self.rules:
            raise AdvancedRiskError("advanced-risk candidate rules must be a non-empty exact tuple")
        if len(self.rules) > MAX_ADVANCED_RISK_RULES:
            raise AdvancedRiskError("advanced-risk candidate exceeds its rule bound")
        for rule in self.rules:
            if type(rule) is not AdvancedRiskRuleBinding:
                raise AdvancedRiskError("advanced-risk candidate rules must be exact")
            rule.__post_init__()
        expected = tuple(sorted(self.rules, key=lambda rule: rule.rule_id))
        if self.rules != expected:
            raise AdvancedRiskError("advanced-risk candidate rules must be canonically ordered")
        rule_ids = tuple(rule.rule_id for rule in self.rules)
        if len(rule_ids) != len(set(rule_ids)):
            raise AdvancedRiskFactConflict("advanced-risk candidate repeats a rule ID")
        rule_kinds = tuple(rule.kind for rule in self.rules)
        if len(rule_kinds) != len(set(rule_kinds)):
            raise AdvancedRiskFactConflict("advanced-risk candidate repeats a rule kind")

    @property
    def candidate_id(self) -> str:
        return canonical_id(
            "advanced-risk-policy-candidate",
            self.policy_id,
            self.policy_version,
            self.environment,
            self.scope_profile_sha256,
        )

    @property
    def missing_rule_kinds(self) -> tuple[AdvancedRiskRuleKind, ...]:
        present = {rule.kind for rule in self.rules}
        return tuple(kind for kind in AdvancedRiskRuleKind if kind not in present)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "policy_candidate",
            self.candidate_id,
            self.policy_id,
            self.policy_version,
            self.environment,
            self.scope_profile_id,
            self.scope_profile_sha256,
            tuple(rule.semantic_sha256 for rule in self.rules),
            self.proposed_at,
            "owner_approval_required",
            "no_threshold_or_action_semantics",
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def owner_approved(self) -> bool:
        return False

    @property
    def trading_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def control_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def activation_effect(self) -> AdvancedRiskEffect:
        return _effect()


@dataclass(frozen=True, slots=True)
class AdvancedRiskEvidenceSource:
    """One exact, ordered source reference retained by an observation."""

    source_kind: str
    source_id: str
    source_sha256: str
    effective_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        _require_text(
            self.source_kind,
            "advanced-risk source kind",
            maximum=64,
        )
        _require_text(self.source_id, "advanced-risk source ID", maximum=128)
        _require_sha256(self.source_sha256, "advanced-risk source_sha256")
        _require_utc(self.effective_at, "advanced-risk source effective_at")
        _require_utc(self.available_at, "advanced-risk source available_at")
        if self.available_at < self.effective_at:
            raise AdvancedRiskError(
                "advanced-risk source availability cannot precede effective time"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_CONTRACT_VERSION,
            "evidence_source",
            self.source_kind,
            self.source_id,
            self.source_sha256,
            self.effective_at,
            self.available_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskRuleObservation:
    """A structural measurement fact with no threshold or control meaning."""

    account_id: str
    environment: str
    idempotency_key: str
    rule: AdvancedRiskRuleBinding
    producer_id: str
    producer_version: str
    producer_authority_sha256: str
    window_started_at: datetime
    window_ended_at: datetime
    observed_at: datetime
    recorded_at: datetime
    completeness: AdvancedRiskObservationCompleteness
    value: Decimal | None
    incomplete_reason: str | None
    sources: tuple[AdvancedRiskEvidenceSource, ...]
    source_count: int
    overflow_source_set_sha256: str | None = None

    def __post_init__(self) -> None:
        for text, field_name, maximum in (
            (self.account_id, "advanced-risk observation account ID", 64),
            (self.environment, "advanced-risk observation environment", 32),
            (self.producer_id, "advanced-risk producer ID", 128),
            (self.producer_version, "advanced-risk producer version", 64),
        ):
            _require_text(text, field_name, maximum=maximum)
        if (
            type(self.idempotency_key) is not str
            or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
        ):
            raise AdvancedRiskError(
                "advanced-risk idempotency key must contain 8-128 safe visible characters"
            )
        if type(self.rule) is not AdvancedRiskRuleBinding:
            raise AdvancedRiskError("advanced-risk observation rule must be exact")
        self.rule.__post_init__()
        _require_sha256(
            self.producer_authority_sha256,
            "advanced-risk producer_authority_sha256",
        )
        for instant, field_name in (
            (self.window_started_at, "advanced-risk window_started_at"),
            (self.window_ended_at, "advanced-risk window_ended_at"),
            (self.observed_at, "advanced-risk observed_at"),
            (self.recorded_at, "advanced-risk recorded_at"),
        ):
            _require_utc(instant, field_name)
        if not (
            self.window_started_at < self.window_ended_at
            and self.window_ended_at <= self.observed_at
            and self.observed_at <= self.recorded_at
        ):
            raise AdvancedRiskError("advanced-risk observation chronology is invalid")
        if type(self.completeness) is not AdvancedRiskObservationCompleteness:
            raise AdvancedRiskError("advanced-risk observation completeness is unsupported")
        if type(self.sources) is not tuple:
            raise AdvancedRiskError("advanced-risk observation sources must be an exact tuple")
        if len(self.sources) > MAX_ADVANCED_RISK_SOURCES:
            raise AdvancedRiskError("advanced-risk observation exceeds its source bound")
        for source in self.sources:
            if type(source) is not AdvancedRiskEvidenceSource:
                raise AdvancedRiskError("advanced-risk observation sources must be exact")
            source.__post_init__()
            if not (
                self.window_started_at <= source.effective_at <= self.window_ended_at
                and source.available_at <= self.observed_at
            ):
                raise AdvancedRiskFactConflict(
                    "advanced-risk observation source lies outside its causal window"
                )
        expected_sources = tuple(
            sorted(
                self.sources,
                key=lambda source: (source.source_kind, source.source_id),
            )
        )
        if self.sources != expected_sources:
            raise AdvancedRiskError("advanced-risk sources must be canonically ordered")
        source_identities = tuple((source.source_kind, source.source_id) for source in self.sources)
        if len(source_identities) != len(set(source_identities)):
            raise AdvancedRiskFactConflict("advanced-risk observation repeats a source")
        if (
            type(self.source_count) is not int
            or self.source_count < 0
            or self.source_count > MAX_ADVANCED_RISK_SOURCE_COUNT
        ):
            raise AdvancedRiskError("advanced-risk source_count is out of range")

        if self.completeness is AdvancedRiskObservationCompleteness.COMPLETE:
            if not self.sources or self.source_count != len(self.sources):
                raise AdvancedRiskError(
                    "complete advanced-risk observation requires every retained source"
                )
            if self.value is None:
                raise AdvancedRiskError(
                    "complete advanced-risk observation requires an exact value"
                )
            object.__setattr__(
                self,
                "value",
                _persisted_decimal(self.value, "advanced-risk observation value"),
            )
            if self.incomplete_reason is not None:
                raise AdvancedRiskError(
                    "complete advanced-risk observation cannot carry an incomplete reason"
                )
            if self.overflow_source_set_sha256 is not None:
                raise AdvancedRiskError(
                    "complete advanced-risk observation cannot carry overflow evidence"
                )
        else:
            if self.value is not None:
                raise AdvancedRiskError("incomplete advanced-risk observation cannot carry a value")
            _require_text(
                self.incomplete_reason or "",
                "advanced-risk incomplete reason",
                maximum=512,
            )
            if self.completeness is AdvancedRiskObservationCompleteness.OVERFLOWED:
                if len(self.sources) != MAX_ADVANCED_RISK_SOURCES or self.source_count <= len(
                    self.sources
                ):
                    raise AdvancedRiskError(
                        "overflowed advanced-risk observation must retain its bounded prefix"
                    )
                _require_sha256(
                    self.overflow_source_set_sha256 or "",
                    "advanced-risk overflow_source_set_sha256",
                )
            else:
                if self.source_count != len(self.sources):
                    raise AdvancedRiskError(
                        "non-overflowed advanced-risk source_count must be exact"
                    )
                if self.overflow_source_set_sha256 is not None:
                    raise AdvancedRiskError(
                        "non-overflowed advanced-risk observation cannot carry overflow evidence"
                    )

    @property
    def observation_id(self) -> str:
        return canonical_id(
            "advanced-risk-observation",
            self.account_id,
            self.environment,
            self.producer_id,
            self.idempotency_key,
        )

    @property
    def source_set_sha256(self) -> str:
        if self.completeness is AdvancedRiskObservationCompleteness.OVERFLOWED:
            assert self.overflow_source_set_sha256 is not None
            return self.overflow_source_set_sha256
        return _sha256(
            (
                ADVANCED_RISK_CONTRACT_VERSION,
                "source_set",
                tuple(source.semantic_sha256 for source in self.sources),
            )
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "rule_observation",
            self.observation_id,
            self.account_id,
            self.environment,
            self.idempotency_key,
            self.rule.semantic_sha256,
            self.producer_id,
            self.producer_version,
            self.producer_authority_sha256,
            self.window_started_at,
            self.window_ended_at,
            self.observed_at,
            self.recorded_at,
            self.completeness,
            self.value,
            self.incomplete_reason,
            self.source_count,
            tuple(source.semantic_sha256 for source in self.sources),
            self.source_set_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def trading_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def control_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def activation_effect(self) -> AdvancedRiskEffect:
        return _effect()


@dataclass(frozen=True, slots=True)
class AdvancedRiskEvidenceBundle:
    """Exact all-rule measurement evidence that remains non-authorizing."""

    account_id: str
    environment: str
    policy_candidate: AdvancedRiskPolicyCandidate
    observations: tuple[AdvancedRiskRuleObservation, ...]
    bound_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "advanced-risk bundle account ID", maximum=64)
        _require_text(self.environment, "advanced-risk bundle environment", maximum=32)
        if type(self.policy_candidate) is not AdvancedRiskPolicyCandidate:
            raise AdvancedRiskError("advanced-risk bundle policy candidate must be exact")
        self.policy_candidate.__post_init__()
        if self.environment != self.policy_candidate.environment:
            raise AdvancedRiskFactConflict("advanced-risk bundle and policy environments differ")
        _require_utc(self.bound_at, "advanced-risk bundle bound_at")
        if self.bound_at < self.policy_candidate.proposed_at:
            raise AdvancedRiskFactConflict(
                "advanced-risk bundle cannot predate its policy candidate"
            )
        if type(self.observations) is not tuple:
            raise AdvancedRiskError("advanced-risk bundle observations must be an exact tuple")
        if any(
            type(observation) is not AdvancedRiskRuleObservation
            for observation in self.observations
        ):
            raise AdvancedRiskError("advanced-risk bundle observations must be exact")
        expected = tuple(
            sorted(self.observations, key=lambda observation: observation.rule.rule_id)
        )
        if self.observations != expected:
            raise AdvancedRiskError("advanced-risk bundle observations must be canonically ordered")
        expected_rules = self.policy_candidate.rules
        if len(self.observations) != len(expected_rules):
            raise AdvancedRiskFactConflict(
                "advanced-risk bundle must contain exactly one observation per candidate rule"
            )
        observation_ids = tuple(observation.observation_id for observation in self.observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise AdvancedRiskFactConflict(
                "advanced-risk bundle repeats an observation idempotency identity"
            )
        for observation, rule in zip(self.observations, expected_rules, strict=True):
            observation.__post_init__()
            if (
                observation.account_id != self.account_id
                or observation.environment != self.environment
                or observation.rule != rule
            ):
                raise AdvancedRiskFactConflict(
                    "advanced-risk bundle observation scope or rule conflicts"
                )
            if observation.completeness is not AdvancedRiskObservationCompleteness.COMPLETE:
                raise AdvancedRiskError(
                    "advanced-risk bundle requires structurally complete observations"
                )
            if observation.recorded_at > self.bound_at:
                raise AdvancedRiskFactConflict(
                    "advanced-risk bundle predates retained observation evidence"
                )

    @property
    def bundle_id(self) -> str:
        return canonical_id(
            "advanced-risk-evidence-bundle",
            self.account_id,
            self.environment,
            self.policy_candidate.semantic_sha256,
            tuple(observation.semantic_sha256 for observation in self.observations),
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_CONTRACT_VERSION,
            "evidence_bundle",
            self.bundle_id,
            self.account_id,
            self.environment,
            self.policy_candidate.semantic_sha256,
            tuple(observation.semantic_sha256 for observation in self.observations),
            self.bound_at,
            "structural_completeness_only",
            "owner_approval_required",
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def trading_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def control_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def activation_effect(self) -> AdvancedRiskEffect:
        return _effect()


@dataclass(frozen=True, slots=True)
class AdvancedRiskEvaluationGate:
    """Explicit fail-closed result while owner activation is unavailable."""

    policy_candidate_id: str
    policy_candidate_sha256: str
    assessed_at: datetime
    readiness: AdvancedRiskPolicyReadiness
    missing_rule_kinds: tuple[AdvancedRiskRuleKind, ...]

    def __post_init__(self) -> None:
        _require_text(
            self.policy_candidate_id,
            "advanced-risk gate policy candidate ID",
            maximum=36,
        )
        _require_sha256(
            self.policy_candidate_sha256,
            "advanced-risk gate policy_candidate_sha256",
        )
        _require_utc(self.assessed_at, "advanced-risk gate assessed_at")
        if self.readiness is not AdvancedRiskPolicyReadiness.OWNER_APPROVAL_REQUIRED:
            raise AdvancedRiskError("advanced-risk policy readiness is unsupported")
        if type(self.missing_rule_kinds) is not tuple:
            raise AdvancedRiskError("advanced-risk gate missing kinds must be an exact tuple")
        if any(type(kind) is not AdvancedRiskRuleKind for kind in self.missing_rule_kinds):
            raise AdvancedRiskError(
                "advanced-risk gate missing kinds must contain exact rule kinds"
            )
        expected = tuple(
            kind for kind in AdvancedRiskRuleKind if kind in set(self.missing_rule_kinds)
        )
        if self.missing_rule_kinds != expected:
            raise AdvancedRiskError(
                "advanced-risk gate missing kinds must be canonically ordered and unique"
            )

    @property
    def can_evaluate(self) -> bool:
        return False

    @property
    def trading_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def control_effect(self) -> AdvancedRiskEffect:
        return _effect()

    @property
    def activation_effect(self) -> AdvancedRiskEffect:
        return _effect()


def assess_advanced_risk_policy(
    candidate: AdvancedRiskPolicyCandidate,
    *,
    assessed_at: datetime,
) -> AdvancedRiskEvaluationGate:
    """Return the explicit non-evaluation gate for an unapproved proposal."""

    if type(candidate) is not AdvancedRiskPolicyCandidate:
        raise AdvancedRiskError("advanced-risk policy assessment requires an exact candidate")
    candidate.__post_init__()
    _require_utc(assessed_at, "advanced-risk gate assessed_at")
    if assessed_at < candidate.proposed_at:
        raise AdvancedRiskError("advanced-risk gate cannot predate its candidate")
    return AdvancedRiskEvaluationGate(
        policy_candidate_id=candidate.candidate_id,
        policy_candidate_sha256=candidate.semantic_sha256,
        assessed_at=assessed_at,
        readiness=AdvancedRiskPolicyReadiness.OWNER_APPROVAL_REQUIRED,
        missing_rule_kinds=candidate.missing_rule_kinds,
    )


def bind_advanced_risk_evidence(
    *,
    account_id: str,
    environment: str,
    policy_candidate: AdvancedRiskPolicyCandidate,
    observations: tuple[AdvancedRiskRuleObservation, ...],
    bound_at: datetime,
) -> AdvancedRiskEvidenceBundle:
    """Bind structurally complete evidence without evaluating or authorizing it."""

    return AdvancedRiskEvidenceBundle(
        account_id=account_id,
        environment=environment,
        policy_candidate=policy_candidate,
        observations=observations,
        bound_at=bound_at,
    )


def require_activated_advanced_risk_policy(
    candidate: AdvancedRiskPolicyCandidate,
) -> None:
    """Fail closed until a separate owner-activation contract is implemented."""

    if type(candidate) is not AdvancedRiskPolicyCandidate:
        raise AdvancedRiskError("advanced-risk activation check requires an exact candidate")
    candidate.__post_init__()
    raise AdvancedRiskPolicyUnapproved(
        "advanced-risk policy candidate has no owner activation receipt"
    )
