"""Owner-approved Phase 5B moderate paper-risk policy.

This module is pure domain policy.  It defines the approved measurement limits
and evaluates already-produced evidence, but it does not authenticate a policy
assignment, reserve capacity, authorize an order, emit a control command, or
call a broker.  Persistence and atomic composition must retain those separate
authority boundaries.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from packages.domain.advanced_risk import (
    MAX_ADVANCED_RISK_SOURCES,
    AdvancedRiskEvidenceSource,
    AdvancedRiskObservationCompleteness,
    AdvancedRiskRuleKind,
)
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import DECIMAL_ARITHMETIC_VERSION
from packages.domain.identifiers import canonical_id

ADVANCED_RISK_POLICY_CONTRACT_VERSION = "phase5b-advanced-risk-policy-v1"
ADVANCED_RISK_POSITIVE_PROJECTION = "ceiling-to-numeric-28-10-v1"
MODERATE_ADVANCED_RISK_POLICY_ID = "phase5b-moderate-paper-rth-etf-v1"
MODERATE_ADVANCED_RISK_POLICY_VERSION = "1"
MODERATE_ADVANCED_RISK_ENVIRONMENT = "paper"
MODERATE_ADVANCED_RISK_INSTRUMENTS = (
    "US-ETF-DIA",
    "US-ETF-IWM",
    "US-ETF-QQQ",
    "US-ETF-SPY",
)
MODERATE_ADVANCED_RISK_SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdvancedRiskPolicyError(ValueError):
    """Approved advanced-risk policy evidence or assessment is malformed."""


class AdvancedRiskPolicyConflict(AdvancedRiskPolicyError):
    """Immutable advanced-risk policy facts conflict."""


class AdvancedRiskEvaluationMode(StrEnum):
    """Closed contexts in which the policy may be evaluated."""

    PRETRADE_NEW_EXPOSURE = "pretrade_new_exposure"
    RUNTIME = "runtime"


class AdvancedRiskDisposition(StrEnum):
    """Closed policy outcomes, ordered separately by evaluation mode."""

    NONE = "none"
    REJECT = "reject"
    PAUSE = "pause"
    HALT = "halt"


class AdvancedRiskThresholdComparator(StrEnum):
    """Exact threshold boundary semantics."""

    STRICTLY_GREATER = "strictly_greater"
    AT_LEAST = "at_least"


class ModerateAdvancedRiskRuleId(StrEnum):
    """Stable rule identities for the approved moderate paper policy."""

    SESSION_LOSS_RATIO = "session_loss_ratio"
    SESSION_DRAWDOWN_RATIO = "session_drawdown_ratio"
    INSTRUMENT_CONCENTRATION_RATIO = "instrument_concentration_ratio"
    GROSS_LEVERAGE_MULTIPLE = "gross_leverage_multiple"
    ABS_NET_LEVERAGE_MULTIPLE = "abs_net_leverage_multiple"
    CASH_ACCOUNT_INTEGRITY_UNHEALTHY = "cash_account_integrity_unhealthy"
    VOLATILITY_MAX_ABS_1M_RETURN_RATIO = "volatility_max_abs_1m_return_ratio"
    SIP_NBBO_FULL_SPREAD_BPS = "sip_nbbo_full_spread_bps"
    PROJECTED_EXECUTION_COST_BPS = "projected_execution_cost_bps"
    REALIZED_EXECUTION_SLIPPAGE_BPS = "realized_execution_slippage_bps"
    BROKER_REJECT_RATE_RATIO = "broker_reject_rate_ratio"
    BROKER_CONSECUTIVE_REJECTS = "broker_consecutive_rejects"
    BROKER_REQUEST_PROJECTED_COUNT = "broker_request_projected_count"
    CLOCK_DRIFT_MILLISECONDS = "clock_drift_milliseconds"
    MARKET_DATA_AGE_SECONDS = "market_data_age_seconds"
    DATA_HEALTH_UNHEALTHY = "data_health_unhealthy"
    UNKNOWN_SUBMISSION_DURATION_SECONDS = "unknown_submission_duration_seconds"
    RECONCILIATION_DURATION_SECONDS = "reconciliation_duration_seconds"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskPolicyError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskPolicyError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskPolicyError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AdvancedRiskPolicyError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise AdvancedRiskPolicyError(f"{field_name} must be UTC")


def advanced_risk_policy_source_set_sha256(
    members: tuple[AdvancedRiskEvidenceSource, ...],
    *,
    source_count: int,
) -> str:
    """Authenticate one exact retained source membership or bounded prefix."""

    if type(members) is not tuple or any(
        type(member) is not AdvancedRiskEvidenceSource for member in members
    ):
        raise AdvancedRiskPolicyError("advanced-risk policy source members must be an exact tuple")
    if len(members) > MAX_ADVANCED_RISK_SOURCES:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy source membership exceeds its durable bound"
        )
    for member in members:
        member.__post_init__()
    expected = tuple(
        sorted(
            members,
            key=lambda member: (member.source_kind, member.source_id),
        )
    )
    if members != expected:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy source members must be canonically ordered"
        )
    identities = tuple((member.source_kind, member.source_id) for member in members)
    if len(identities) != len(set(identities)):
        raise AdvancedRiskPolicyError("advanced-risk policy source membership repeats an identity")
    if type(source_count) is not int or source_count < len(members) or source_count > (1 << 63) - 1:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy source_count is outside its durable bound"
        )
    if source_count > len(members) and len(members) != MAX_ADVANCED_RISK_SOURCES:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy overflow must retain its bounded source prefix"
        )
    return _sha256(
        (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            "policy_observation_source_set",
            source_count,
            tuple(member.semantic_sha256 for member in members),
        )
    )


def _persisted_decimal(value: Decimal, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise AdvancedRiskPolicyError(f"{field_name} must be a finite exact Decimal")
    try:
        return canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise AdvancedRiskPolicyError(str(error)) from error


def conservative_positive_risk_decimal(value: Decimal, field_name: str) -> Decimal:
    """Project a non-negative risk value upward to the durable 10-place scale.

    Producers must use this rule when an exact division has more than ten
    fractional places.  A positive breach can therefore never be rounded down
    to threshold equality.
    """

    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise AdvancedRiskPolicyError(f"{field_name} must be a finite non-negative Decimal")
    sign, digits, raw_exponent = value.as_tuple()
    if sign:
        raise AdvancedRiskPolicyError(f"{field_name} must be non-negative")
    exponent = int(raw_exponent)
    if exponent >= -10:
        return _persisted_decimal(value, field_name)
    if len(digits) + exponent - 1 < -10:
        return _persisted_decimal(Decimal("0.0000000001"), field_name)
    coefficient = int("".join(str(digit) for digit in digits))
    divisor = 10 ** (-10 - exponent)
    projected, remainder = divmod(coefficient, divisor)
    if remainder:
        projected += 1
    projected_digits = tuple(int(character) for character in str(projected))
    return _persisted_decimal(Decimal((0, projected_digits, -10)), field_name)


def _authority_sha256(authority_kind: str, authority_id: str) -> str:
    return _sha256(
        (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            "required_authority",
            authority_kind,
            authority_id,
        )
    )


@dataclass(frozen=True, slots=True)
class ModerateAdvancedRiskRule:
    """One fixed rule definition in the owner-approved policy."""

    rule_id: ModerateAdvancedRiskRuleId
    kind: AdvancedRiskRuleKind
    measurement_unit: str
    measurement_scope: str
    producer_authority_id: str
    producer_authority_sha256: str
    source_authority_id: str
    source_authority_sha256: str
    comparator: AdvancedRiskThresholdComparator
    pretrade_reject_threshold: Decimal | None
    runtime_pause_threshold: Decimal | None
    runtime_halt_threshold: Decimal | None
    maximum_evidence_age_seconds: int | None = None
    minimum_complete_samples: int = 1
    exact_complete_samples: bool = False
    runtime_pause_minimum_qualifying_count: int = 0
    runtime_halt_minimum_qualifying_count: int = 0

    def __post_init__(self) -> None:
        if type(self.rule_id) is not ModerateAdvancedRiskRuleId:
            raise AdvancedRiskPolicyError("advanced-risk rule ID is unsupported")
        if type(self.kind) is not AdvancedRiskRuleKind:
            raise AdvancedRiskPolicyError("advanced-risk rule kind is unsupported")
        for value, field_name in (
            (self.measurement_unit, "advanced-risk measurement unit"),
            (self.measurement_scope, "advanced-risk measurement scope"),
            (self.producer_authority_id, "advanced-risk producer authority ID"),
            (self.source_authority_id, "advanced-risk source authority ID"),
        ):
            _require_text(value, field_name)
        _require_sha256(
            self.producer_authority_sha256,
            "advanced-risk producer_authority_sha256",
        )
        _require_sha256(self.source_authority_sha256, "advanced-risk source_authority_sha256")
        if type(self.comparator) is not AdvancedRiskThresholdComparator:
            raise AdvancedRiskPolicyError("advanced-risk comparator is unsupported")
        for field_name in (
            "pretrade_reject_threshold",
            "runtime_pause_threshold",
            "runtime_halt_threshold",
        ):
            threshold_value = getattr(self, field_name)
            if threshold_value is not None:
                threshold_value = _persisted_decimal(
                    threshold_value,
                    f"advanced-risk {field_name}",
                )
                if threshold_value < 0:
                    raise AdvancedRiskPolicyError(
                        f"advanced-risk {field_name} must be non-negative"
                    )
                object.__setattr__(self, field_name, threshold_value)
        if type(self.minimum_complete_samples) is not int or self.minimum_complete_samples < 1:
            raise AdvancedRiskPolicyError(
                "advanced-risk minimum_complete_samples must be a positive integer"
            )
        if type(self.exact_complete_samples) is not bool:
            raise AdvancedRiskPolicyError("advanced-risk exact_complete_samples must be bool")
        for field_name in (
            "runtime_pause_minimum_qualifying_count",
            "runtime_halt_minimum_qualifying_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise AdvancedRiskPolicyError(f"advanced-risk {field_name} is invalid")
        if self.runtime_halt_threshold is not None and self.runtime_pause_threshold is None:
            raise AdvancedRiskPolicyError("advanced-risk halt threshold requires pause threshold")
        if self.maximum_evidence_age_seconds is not None and (
            type(self.maximum_evidence_age_seconds) is not int
            or self.maximum_evidence_age_seconds < 1
        ):
            raise AdvancedRiskPolicyError(
                "advanced-risk maximum evidence age must be a positive integer"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "moderate_rule",
            self.rule_id,
            self.kind,
            self.measurement_unit,
            self.measurement_scope,
            self.producer_authority_id,
            self.producer_authority_sha256,
            self.source_authority_id,
            self.source_authority_sha256,
            self.comparator,
            self.pretrade_reject_threshold,
            self.runtime_pause_threshold,
            self.runtime_halt_threshold,
            self.maximum_evidence_age_seconds,
            self.minimum_complete_samples,
            self.exact_complete_samples,
            self.runtime_pause_minimum_qualifying_count,
            self.runtime_halt_minimum_qualifying_count,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


def _rule(
    rule_id: ModerateAdvancedRiskRuleId,
    kind: AdvancedRiskRuleKind,
    unit: str,
    scope: str,
    authority_id: str,
    *,
    pretrade: str | None = None,
    pause: str | None = None,
    halt: str | None = None,
    comparator: AdvancedRiskThresholdComparator = (
        AdvancedRiskThresholdComparator.STRICTLY_GREATER
    ),
    maximum_age_seconds: int | None = None,
    minimum_samples: int = 1,
    exact_samples: bool = False,
    pause_qualifying: int = 0,
    halt_qualifying: int = 0,
) -> ModerateAdvancedRiskRule:
    producer_id = f"{authority_id}-producer-v1"
    source_id = f"{authority_id}-source-v1"
    return ModerateAdvancedRiskRule(
        rule_id=rule_id,
        kind=kind,
        measurement_unit=unit,
        measurement_scope=scope,
        producer_authority_id=producer_id,
        producer_authority_sha256=_authority_sha256("producer", producer_id),
        source_authority_id=source_id,
        source_authority_sha256=_authority_sha256("source", source_id),
        comparator=comparator,
        pretrade_reject_threshold=None if pretrade is None else Decimal(pretrade),
        runtime_pause_threshold=None if pause is None else Decimal(pause),
        runtime_halt_threshold=None if halt is None else Decimal(halt),
        maximum_evidence_age_seconds=maximum_age_seconds,
        minimum_complete_samples=minimum_samples,
        exact_complete_samples=exact_samples,
        runtime_pause_minimum_qualifying_count=pause_qualifying,
        runtime_halt_minimum_qualifying_count=halt_qualifying,
    )


MODERATE_ADVANCED_RISK_RULES = (
    _rule(
        ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO,
        AdvancedRiskRuleKind.SESSION_LOSS,
        "equity_ratio",
        "account_rth_session",
        "flow_adjusted_session_equity",
        pause="0.02",
        halt="0.03",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.SESSION_DRAWDOWN_RATIO,
        AdvancedRiskRuleKind.SESSION_DRAWDOWN,
        "equity_ratio",
        "account_rth_session",
        "flow_adjusted_session_high_water",
        pause="0.025",
        halt="0.04",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        AdvancedRiskRuleKind.CONCENTRATION,
        "nav_ratio",
        "instrument_current_committed_and_proposed",
        "canonical_position_and_reservation_projection",
        pretrade="0.35",
        pause="0.35",
        halt="0.50",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
        AdvancedRiskRuleKind.LEVERAGE,
        "nav_multiple",
        "account_current_committed_and_proposed",
        "canonical_gross_exposure_projection",
        pretrade="1.00",
        pause="1.00",
        halt="1.10",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
        AdvancedRiskRuleKind.LEVERAGE,
        "nav_multiple",
        "account_current_committed_and_proposed",
        "canonical_abs_net_exposure_projection",
        pretrade="1.00",
        pause="1.00",
        halt="1.10",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
        AdvancedRiskRuleKind.LEVERAGE,
        "binary",
        "account_long_only_cash_invariants",
        "canonical_gross_and_net_exposure_projection",
        pretrade="0",
        pause="0",
        halt="0",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
        AdvancedRiskRuleKind.VOLATILITY,
        "simple_return_ratio",
        "instrument_30_consecutive_rth_returns",
        "admitted_causal_rth_minute_bars",
        pretrade="0.015",
        pause="0.015",
        halt="0.03",
        minimum_samples=30,
        exact_samples=True,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
        AdvancedRiskRuleKind.SPREAD,
        "basis_points",
        "instrument_fresh_rth_sip_nbbo",
        "entitled_consolidated_sip_quote",
        pretrade="20",
        pause="20",
        halt="50",
        maximum_age_seconds=5,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
        AdvancedRiskRuleKind.SLIPPAGE,
        "basis_points",
        "proposed_instrument_half_spread_plus_adverse_model",
        "versioned_pretrade_execution_cost",
        pretrade="25",
        maximum_age_seconds=5,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS,
        AdvancedRiskRuleKind.SLIPPAGE,
        "basis_points",
        "account_last_20_eligible_fills_within_30_minutes",
        "provider_execution_and_arrival_sip_mid",
        pause="15",
        halt="30",
        minimum_samples=20,
        exact_samples=True,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO,
        AdvancedRiskRuleKind.BROKER_REJECT_RATE,
        "definitive_outcome_ratio",
        "account_trailing_10_minutes",
        "canonical_correlated_broker_outcomes",
        pause="0.10",
        halt="0.25",
        minimum_samples=10,
        pause_qualifying=3,
        halt_qualifying=5,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.BROKER_CONSECUTIVE_REJECTS,
        AdvancedRiskRuleKind.BROKER_REJECT_RATE,
        "definitive_reject_count",
        "account_trailing_10_minute_definitive_suffix",
        "canonical_correlated_broker_outcomes",
        pause="3",
        halt="5",
        comparator=AdvancedRiskThresholdComparator.AT_LEAST,
    ),
    _rule(
        ModerateAdvancedRiskRuleId.BROKER_REQUEST_PROJECTED_COUNT,
        AdvancedRiskRuleKind.BROKER_RATE_LIMIT,
        "request_count",
        "account_trailing_60_seconds",
        "durable_broker_request_budget",
        pretrade="160",
        pause="180",
        halt="200",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.CLOCK_DRIFT_MILLISECONDS,
        AdvancedRiskRuleKind.CLOCK_HEALTH,
        "milliseconds",
        "runtime_clock",
        "authenticated_clock_health",
        pretrade="1000",
        pause="1000",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.MARKET_DATA_AGE_SECONDS,
        AdvancedRiskRuleKind.DATA_HEALTH,
        "seconds",
        "causal_market_data",
        "admitted_market_data_freshness",
        pretrade="15",
        pause="15",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
        AdvancedRiskRuleKind.DATA_HEALTH,
        "binary",
        "required_runtime_data_lanes",
        "authenticated_data_health",
        pretrade="0",
        pause="0",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.UNKNOWN_SUBMISSION_DURATION_SECONDS,
        AdvancedRiskRuleKind.UNKNOWN_DURATION,
        "seconds",
        "oldest_account_unknown_submission",
        "durable_unknown_submission_journal",
        pretrade="60",
        pause="60",
    ),
    _rule(
        ModerateAdvancedRiskRuleId.RECONCILIATION_DURATION_SECONDS,
        AdvancedRiskRuleKind.RECONCILIATION_DURATION,
        "seconds",
        "account_unresolved_reconciliation",
        "qualified_reconciliation_projection",
        pretrade="120",
        pause="120",
    ),
)

_RULE_BY_ID = {rule.rule_id: rule for rule in MODERATE_ADVANCED_RISK_RULES}
_INSTRUMENT_SCOPED_RULES = {
    ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
    ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
    ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
    ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
}
_SAMPLE_INSUFFICIENCY_ALLOWED = {
    ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS,
    ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO,
}


@dataclass(frozen=True, slots=True)
class ModerateAdvancedRiskPolicy:
    """Content-addressed approved definition, not an authenticated assignment."""

    policy_id: str
    policy_version: str
    environment: str
    instruments: tuple[str, ...]
    market_session: str
    position_scope: str
    rules: tuple[ModerateAdvancedRiskRule, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.policy_id, "advanced-risk policy ID"),
            (self.policy_version, "advanced-risk policy version"),
            (self.environment, "advanced-risk environment"),
            (self.market_session, "advanced-risk market session"),
            (self.position_scope, "advanced-risk position scope"),
        ):
            _require_text(value, field_name)
        if self.environment != MODERATE_ADVANCED_RISK_ENVIRONMENT:
            raise AdvancedRiskPolicyError("moderate advanced-risk policy is paper-only")
        if self.instruments != MODERATE_ADVANCED_RISK_INSTRUMENTS:
            raise AdvancedRiskPolicyError(
                "moderate advanced-risk policy requires canonical DIA/IWM/QQQ/SPY IDs"
            )
        if self.market_session != "us_equities_rth" or self.position_scope != "long_only":
            raise AdvancedRiskPolicyError(
                "moderate advanced-risk policy requires long-only U.S. equities RTH"
            )
        if type(self.rules) is not tuple or self.rules != MODERATE_ADVANCED_RISK_RULES:
            raise AdvancedRiskPolicyError("moderate advanced-risk rules are fixed")
        if any(type(rule) is not ModerateAdvancedRiskRule for rule in self.rules):
            raise AdvancedRiskPolicyError("moderate advanced-risk rules must be exact")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "moderate_policy",
            self.policy_id,
            self.policy_version,
            self.environment,
            self.instruments,
            tuple(
                zip(
                    self.instruments,
                    MODERATE_ADVANCED_RISK_SYMBOLS,
                    strict=True,
                )
            ),
            self.market_session,
            self.position_scope,
            tuple(rule.semantic_sha256 for rule in self.rules),
            "strict_gt_except_consecutive_reject_count_at_least",
            "pretrade_reject_never_emits_control_trip",
            "runtime_pause_or_halt_requires_durable_operational_trip",
            "manual_rearm_only",
            "definition_only_not_authenticated_assignment",
            ADVANCED_RISK_POSITIVE_PROJECTION,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


MODERATE_ADVANCED_RISK_POLICY = ModerateAdvancedRiskPolicy(
    policy_id=MODERATE_ADVANCED_RISK_POLICY_ID,
    policy_version=MODERATE_ADVANCED_RISK_POLICY_VERSION,
    environment=MODERATE_ADVANCED_RISK_ENVIRONMENT,
    instruments=MODERATE_ADVANCED_RISK_INSTRUMENTS,
    market_session="us_equities_rth",
    position_scope="long_only",
    rules=MODERATE_ADVANCED_RISK_RULES,
)
MODERATE_ADVANCED_RISK_POLICY_SHA256 = MODERATE_ADVANCED_RISK_POLICY.semantic_sha256


@dataclass(frozen=True, slots=True)
class AdvancedRiskPolicyObservation:
    """One normalized metric with exact authority, source, and causal evidence."""

    account_id: str
    environment: str
    rule_id: ModerateAdvancedRiskRuleId
    subject_id: str
    completeness: AdvancedRiskObservationCompleteness
    value: Decimal | None
    sample_count: int
    qualifying_count: int | None
    producer_authority_sha256: str
    source_authority_sha256: str
    source_set_sha256: str
    evidence_sha256: str
    window_started_at: datetime
    window_ended_at: datetime
    observed_at: datetime
    recorded_at: datetime
    incomplete_reason: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.account_id, "advanced-risk observation account ID", maximum=64)
        _require_text(self.environment, "advanced-risk observation environment", maximum=32)
        if self.environment != MODERATE_ADVANCED_RISK_ENVIRONMENT:
            raise AdvancedRiskPolicyError("moderate advanced-risk observations are paper-only")
        if type(self.rule_id) is not ModerateAdvancedRiskRuleId:
            raise AdvancedRiskPolicyError("advanced-risk observation rule ID is unsupported")
        _require_text(self.subject_id, "advanced-risk observation subject ID")
        if self.rule_id in _INSTRUMENT_SCOPED_RULES:
            if self.subject_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS:
                raise AdvancedRiskPolicyError(
                    "instrument-scoped advanced-risk observation is outside policy scope"
                )
        elif self.subject_id != self.account_id:
            raise AdvancedRiskPolicyError(
                "account-scoped advanced-risk observation subject must equal account ID"
            )
        if type(self.completeness) is not AdvancedRiskObservationCompleteness:
            raise AdvancedRiskPolicyError("advanced-risk observation completeness is unsupported")
        if type(self.sample_count) is not int or self.sample_count < 0:
            raise AdvancedRiskPolicyError(
                "advanced-risk observation sample_count must be non-negative"
            )
        if self.qualifying_count is not None and (
            type(self.qualifying_count) is not int
            or self.qualifying_count < 0
            or self.qualifying_count > self.sample_count
        ):
            raise AdvancedRiskPolicyError("advanced-risk observation qualifying_count is invalid")
        for digest_value, field_name in (
            (self.producer_authority_sha256, "advanced-risk producer_authority_sha256"),
            (self.source_authority_sha256, "advanced-risk source_authority_sha256"),
            (self.source_set_sha256, "advanced-risk source_set_sha256"),
            (self.evidence_sha256, "advanced-risk evidence_sha256"),
        ):
            _require_sha256(digest_value, field_name)
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
            raise AdvancedRiskPolicyError("advanced-risk observation chronology is invalid")
        if self.completeness is AdvancedRiskObservationCompleteness.COMPLETE:
            if self.value is None:
                raise AdvancedRiskPolicyError(
                    "complete advanced-risk observation requires an exact value"
                )
            observed_value = _persisted_decimal(
                self.value,
                "advanced-risk observation value",
            )
            if (
                observed_value < 0
                and self.rule_id is not ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS
            ):
                raise AdvancedRiskPolicyError(
                    "advanced-risk observation value must be non-negative"
                )
            object.__setattr__(self, "value", observed_value)
            if self.incomplete_reason is not None:
                raise AdvancedRiskPolicyError(
                    "complete advanced-risk observation cannot carry an incomplete reason"
                )
        else:
            if self.value is not None:
                raise AdvancedRiskPolicyError(
                    "incomplete advanced-risk observation cannot carry a value"
                )
            _require_text(
                self.incomplete_reason or "",
                "advanced-risk incomplete reason",
                maximum=512,
            )

    @property
    def observation_id(self) -> str:
        return canonical_id(
            "moderate-advanced-risk-observation",
            self.account_id,
            self.environment,
            self.rule_id,
            self.subject_id,
            self.evidence_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "policy_observation",
            self.observation_id,
            self.account_id,
            self.environment,
            self.rule_id,
            self.subject_id,
            self.completeness,
            self.value,
            self.sample_count,
            self.qualifying_count,
            self.producer_authority_sha256,
            self.source_authority_sha256,
            self.source_set_sha256,
            self.evidence_sha256,
            self.window_started_at,
            self.window_ended_at,
            self.observed_at,
            self.recorded_at,
            self.incomplete_reason,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskRuleAssessment:
    """Deterministic evaluation of one exact observation."""

    account_id: str
    environment: str
    policy_id: str
    policy_sha256: str
    mode: AdvancedRiskEvaluationMode
    rule_id: ModerateAdvancedRiskRuleId
    subject_id: str
    observation_sha256: str
    evidence_sha256: str
    producer_authority_sha256: str
    source_authority_sha256: str
    source_set_sha256: str
    input_completeness: AdvancedRiskObservationCompleteness
    effective_completeness: AdvancedRiskObservationCompleteness
    observed_value: Decimal | None
    sample_count: int
    qualifying_count: int | None
    threshold: Decimal | None
    comparator: AdvancedRiskThresholdComparator | None
    disposition: AdvancedRiskDisposition
    reason_code: str
    assessed_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "advanced-risk assessment account ID", maximum=64)
        _require_text(self.environment, "advanced-risk assessment environment", maximum=32)
        _require_text(self.policy_id, "advanced-risk assessment policy ID")
        _require_sha256(self.policy_sha256, "advanced-risk assessment policy_sha256")
        if (
            self.environment != MODERATE_ADVANCED_RISK_ENVIRONMENT
            or self.policy_id != MODERATE_ADVANCED_RISK_POLICY_ID
            or self.policy_sha256 != MODERATE_ADVANCED_RISK_POLICY_SHA256
        ):
            raise AdvancedRiskPolicyConflict(
                "advanced-risk assessment is not bound to the fixed moderate policy"
            )
        if type(self.mode) is not AdvancedRiskEvaluationMode:
            raise AdvancedRiskPolicyError("advanced-risk assessment mode is unsupported")
        if type(self.rule_id) is not ModerateAdvancedRiskRuleId:
            raise AdvancedRiskPolicyError("advanced-risk assessment rule ID is unsupported")
        _require_text(self.subject_id, "advanced-risk assessment subject ID")
        if self.rule_id in _INSTRUMENT_SCOPED_RULES:
            if self.subject_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS:
                raise AdvancedRiskPolicyError(
                    "instrument-scoped advanced-risk assessment is outside policy scope"
                )
        elif self.subject_id != self.account_id:
            raise AdvancedRiskPolicyError(
                "account-scoped advanced-risk assessment subject must equal account ID"
            )
        for value, field_name in (
            (self.observation_sha256, "advanced-risk assessment observation_sha256"),
            (self.evidence_sha256, "advanced-risk assessment evidence_sha256"),
            (
                self.producer_authority_sha256,
                "advanced-risk assessment producer_authority_sha256",
            ),
            (self.source_authority_sha256, "advanced-risk assessment source_authority_sha256"),
            (self.source_set_sha256, "advanced-risk assessment source_set_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.input_completeness) is not AdvancedRiskObservationCompleteness:
            raise AdvancedRiskPolicyError("advanced-risk input completeness is unsupported")
        if type(self.effective_completeness) is not AdvancedRiskObservationCompleteness:
            raise AdvancedRiskPolicyError("advanced-risk effective completeness is unsupported")
        if self.observed_value is not None:
            if (
                self.observed_value < 0
                and self.rule_id is not ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS
            ):
                raise AdvancedRiskPolicyError(
                    "advanced-risk assessment observed value must be non-negative"
                )
            object.__setattr__(
                self,
                "observed_value",
                _persisted_decimal(
                    self.observed_value,
                    "advanced-risk assessment observed value",
                ),
            )
        if self.threshold is not None:
            object.__setattr__(
                self,
                "threshold",
                _persisted_decimal(self.threshold, "advanced-risk assessment threshold"),
            )
        if (
            self.comparator is not None
            and type(self.comparator) is not AdvancedRiskThresholdComparator
        ):
            raise AdvancedRiskPolicyError("advanced-risk assessment comparator is unsupported")
        if type(self.disposition) is not AdvancedRiskDisposition:
            raise AdvancedRiskPolicyError("advanced-risk assessment disposition is unsupported")
        if type(self.sample_count) is not int or self.sample_count < 0:
            raise AdvancedRiskPolicyError(
                "advanced-risk assessment sample_count must be non-negative"
            )
        if self.qualifying_count is not None and (
            type(self.qualifying_count) is not int
            or self.qualifying_count < 0
            or self.qualifying_count > self.sample_count
        ):
            raise AdvancedRiskPolicyError("advanced-risk assessment qualifying_count is invalid")
        _require_text(self.reason_code, "advanced-risk assessment reason code")
        _require_utc(self.assessed_at, "advanced-risk assessment assessed_at")
        if self.mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE:
            if self.disposition not in {
                AdvancedRiskDisposition.NONE,
                AdvancedRiskDisposition.REJECT,
            }:
                raise AdvancedRiskPolicyError(
                    "pretrade advanced-risk assessment may only pass or reject"
                )
        elif self.disposition is AdvancedRiskDisposition.REJECT:
            raise AdvancedRiskPolicyError("runtime advanced-risk assessment cannot reject")

    @property
    def requires_control_trip(self) -> bool:
        return self.mode is AdvancedRiskEvaluationMode.RUNTIME and self.disposition in {
            AdvancedRiskDisposition.PAUSE,
            AdvancedRiskDisposition.HALT,
        }

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "rule_assessment",
            self.account_id,
            self.environment,
            self.policy_id,
            self.policy_sha256,
            self.mode,
            self.rule_id,
            self.subject_id,
            self.observation_sha256,
            self.evidence_sha256,
            self.producer_authority_sha256,
            self.source_authority_sha256,
            self.source_set_sha256,
            self.input_completeness,
            self.effective_completeness,
            self.observed_value,
            self.sample_count,
            self.qualifying_count,
            self.threshold,
            self.comparator,
            self.disposition,
            self.reason_code,
            self.assessed_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _threshold_breached(
    value: Decimal,
    threshold: Decimal,
    comparator: AdvancedRiskThresholdComparator,
) -> bool:
    if comparator is AdvancedRiskThresholdComparator.STRICTLY_GREATER:
        return value > threshold
    return value >= threshold


def _fail_closed_disposition(mode: AdvancedRiskEvaluationMode) -> AdvancedRiskDisposition:
    if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE:
        return AdvancedRiskDisposition.REJECT
    return AdvancedRiskDisposition.PAUSE


def _effective_completeness(
    observation: AdvancedRiskPolicyObservation,
    rule: ModerateAdvancedRiskRule,
    assessed_at: datetime,
) -> tuple[AdvancedRiskObservationCompleteness, str | None]:
    if (
        observation.producer_authority_sha256 != rule.producer_authority_sha256
        or observation.source_authority_sha256 != rule.source_authority_sha256
    ):
        return AdvancedRiskObservationCompleteness.UNAVAILABLE, "authority_mismatch"
    if observation.completeness is not AdvancedRiskObservationCompleteness.COMPLETE:
        return observation.completeness, None
    if (
        rule.maximum_evidence_age_seconds is not None
        and assessed_at - observation.observed_at
        >= timedelta(seconds=rule.maximum_evidence_age_seconds)
    ):
        return AdvancedRiskObservationCompleteness.UNAVAILABLE, "evidence_stale"
    if observation.sample_count < rule.minimum_complete_samples:
        return AdvancedRiskObservationCompleteness.INSUFFICIENT, "sample_minimum_not_met"
    if rule.exact_complete_samples and observation.sample_count != rule.minimum_complete_samples:
        return AdvancedRiskObservationCompleteness.UNAVAILABLE, "sample_contract_mismatch"
    if rule.rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO:
        if observation.qualifying_count is None:
            return AdvancedRiskObservationCompleteness.UNAVAILABLE, "qualifying_count_missing"
    elif observation.qualifying_count is not None:
        return AdvancedRiskObservationCompleteness.UNAVAILABLE, "unexpected_qualifying_count"
    return AdvancedRiskObservationCompleteness.COMPLETE, None


def _mode_is_applicable(
    rule: ModerateAdvancedRiskRule,
    mode: AdvancedRiskEvaluationMode,
) -> bool:
    if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE:
        return rule.pretrade_reject_threshold is not None
    return rule.runtime_pause_threshold is not None


def evaluate_moderate_advanced_risk(
    observation: AdvancedRiskPolicyObservation,
    *,
    mode: AdvancedRiskEvaluationMode,
    assessed_at: datetime,
) -> AdvancedRiskRuleAssessment:
    """Evaluate one observation without authorizing or emitting a control command."""

    if type(observation) is not AdvancedRiskPolicyObservation:
        raise AdvancedRiskPolicyError("advanced-risk evaluation requires an exact observation")
    observation.__post_init__()
    if type(mode) is not AdvancedRiskEvaluationMode:
        raise AdvancedRiskPolicyError("advanced-risk evaluation mode is unsupported")
    _require_utc(assessed_at, "advanced-risk assessed_at")
    if assessed_at < observation.recorded_at:
        raise AdvancedRiskPolicyError("advanced-risk assessment cannot predate its evidence")
    rule = _RULE_BY_ID[observation.rule_id]
    effective, downgrade_reason = _effective_completeness(
        observation,
        rule,
        assessed_at,
    )
    disposition = AdvancedRiskDisposition.NONE
    threshold: Decimal | None = None
    comparator: AdvancedRiskThresholdComparator | None = None
    reason_code = "rule_not_applicable_in_mode"

    if _mode_is_applicable(rule, mode):
        if effective is not AdvancedRiskObservationCompleteness.COMPLETE:
            insufficient_is_allowed = (
                effective is AdvancedRiskObservationCompleteness.INSUFFICIENT
                and rule.rule_id in _SAMPLE_INSUFFICIENCY_ALLOWED
                and observation.sample_count < rule.minimum_complete_samples
            )
            if insufficient_is_allowed:
                reason_code = "sample_minimum_not_met_no_action"
            else:
                disposition = _fail_closed_disposition(mode)
                reason_code = downgrade_reason or f"evidence_{effective.value}"
        else:
            assert observation.value is not None
            comparator = rule.comparator
            if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE:
                assert rule.pretrade_reject_threshold is not None
                threshold = rule.pretrade_reject_threshold
                if _threshold_breached(observation.value, threshold, comparator):
                    disposition = AdvancedRiskDisposition.REJECT
                    reason_code = "pretrade_limit_breached"
                else:
                    reason_code = "within_pretrade_limit"
            else:
                assert rule.runtime_pause_threshold is not None
                pause_qualifies = rule.runtime_pause_minimum_qualifying_count == 0 or (
                    observation.qualifying_count is not None
                    and observation.qualifying_count >= rule.runtime_pause_minimum_qualifying_count
                )
                halt_qualifies = rule.runtime_halt_minimum_qualifying_count == 0 or (
                    observation.qualifying_count is not None
                    and observation.qualifying_count >= rule.runtime_halt_minimum_qualifying_count
                )
                if (
                    rule.runtime_halt_threshold is not None
                    and halt_qualifies
                    and _threshold_breached(
                        observation.value,
                        rule.runtime_halt_threshold,
                        comparator,
                    )
                ):
                    disposition = AdvancedRiskDisposition.HALT
                    threshold = rule.runtime_halt_threshold
                    reason_code = "runtime_halt_limit_breached"
                elif pause_qualifies and _threshold_breached(
                    observation.value,
                    rule.runtime_pause_threshold,
                    comparator,
                ):
                    disposition = AdvancedRiskDisposition.PAUSE
                    threshold = rule.runtime_pause_threshold
                    reason_code = "runtime_pause_limit_breached"
                else:
                    threshold = rule.runtime_pause_threshold
                    reason_code = "within_runtime_limit"

    return AdvancedRiskRuleAssessment(
        account_id=observation.account_id,
        environment=observation.environment,
        policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode=mode,
        rule_id=observation.rule_id,
        subject_id=observation.subject_id,
        observation_sha256=observation.semantic_sha256,
        evidence_sha256=observation.evidence_sha256,
        producer_authority_sha256=observation.producer_authority_sha256,
        source_authority_sha256=observation.source_authority_sha256,
        source_set_sha256=observation.source_set_sha256,
        input_completeness=observation.completeness,
        effective_completeness=effective,
        observed_value=observation.value,
        sample_count=observation.sample_count,
        qualifying_count=observation.qualifying_count,
        threshold=threshold,
        comparator=comparator,
        disposition=disposition,
        reason_code=reason_code,
        assessed_at=assessed_at,
    )


@dataclass(frozen=True, slots=True)
class AdvancedRiskPolicyAssessment:
    """Severity aggregation over exact rule assessments in one evaluation mode."""

    account_id: str
    environment: str
    policy_id: str
    policy_sha256: str
    mode: AdvancedRiskEvaluationMode
    rule_assessments: tuple[AdvancedRiskRuleAssessment, ...]
    disposition: AdvancedRiskDisposition
    assessed_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "advanced-risk aggregate account ID", maximum=64)
        _require_text(self.environment, "advanced-risk aggregate environment", maximum=32)
        _require_text(self.policy_id, "advanced-risk aggregate policy ID")
        _require_sha256(self.policy_sha256, "advanced-risk aggregate policy_sha256")
        if (
            self.environment != MODERATE_ADVANCED_RISK_ENVIRONMENT
            or self.policy_id != MODERATE_ADVANCED_RISK_POLICY_ID
            or self.policy_sha256 != MODERATE_ADVANCED_RISK_POLICY_SHA256
        ):
            raise AdvancedRiskPolicyConflict(
                "advanced-risk aggregate is not bound to the fixed moderate policy"
            )
        if type(self.mode) is not AdvancedRiskEvaluationMode:
            raise AdvancedRiskPolicyError("advanced-risk aggregate mode is unsupported")
        if type(self.rule_assessments) is not tuple or not self.rule_assessments:
            raise AdvancedRiskPolicyError(
                "advanced-risk aggregate requires a non-empty exact tuple"
            )
        if any(
            type(assessment) is not AdvancedRiskRuleAssessment
            for assessment in self.rule_assessments
        ):
            raise AdvancedRiskPolicyError("advanced-risk aggregate assessments must be exact")
        expected = tuple(
            sorted(
                self.rule_assessments,
                key=lambda item: (item.rule_id.value, item.subject_id),
            )
        )
        if self.rule_assessments != expected:
            raise AdvancedRiskPolicyError(
                "advanced-risk aggregate assessments must be canonically ordered"
            )
        identities = tuple((item.rule_id, item.subject_id) for item in self.rule_assessments)
        if len(identities) != len(set(identities)):
            raise AdvancedRiskPolicyConflict("advanced-risk aggregate repeats a rule and subject")
        for item in self.rule_assessments:
            if (
                item.account_id != self.account_id
                or item.environment != self.environment
                or item.policy_id != self.policy_id
                or item.policy_sha256 != self.policy_sha256
                or item.mode is not self.mode
            ):
                raise AdvancedRiskPolicyConflict(
                    "advanced-risk aggregate assessment scope conflicts"
                )
        if type(self.disposition) is not AdvancedRiskDisposition:
            raise AdvancedRiskPolicyError("advanced-risk aggregate disposition is unsupported")
        _require_utc(self.assessed_at, "advanced-risk aggregate assessed_at")
        if any(item.assessed_at > self.assessed_at for item in self.rule_assessments):
            raise AdvancedRiskPolicyError(
                "advanced-risk aggregate cannot predate a rule assessment"
            )
        expected_disposition = _aggregate_disposition(self.mode, self.rule_assessments)
        if self.disposition is not expected_disposition:
            raise AdvancedRiskPolicyConflict(
                "advanced-risk aggregate disposition conflicts with its rule assessments"
            )

    @property
    def assessment_id(self) -> str:
        return canonical_id(
            "moderate-advanced-risk-assessment",
            self.account_id,
            self.environment,
            self.policy_sha256,
            self.mode,
            tuple(item.semantic_sha256 for item in self.rule_assessments),
        )

    @property
    def requires_control_trip(self) -> bool:
        return self.mode is AdvancedRiskEvaluationMode.RUNTIME and self.disposition in {
            AdvancedRiskDisposition.PAUSE,
            AdvancedRiskDisposition.HALT,
        }

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            "policy_assessment",
            self.assessment_id,
            self.account_id,
            self.environment,
            self.policy_id,
            self.policy_sha256,
            self.mode,
            tuple(item.semantic_sha256 for item in self.rule_assessments),
            self.disposition,
            self.assessed_at,
            "assessment_only_not_authorization_or_authenticated_assignment",
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _aggregate_disposition(
    mode: AdvancedRiskEvaluationMode,
    assessments: tuple[AdvancedRiskRuleAssessment, ...],
) -> AdvancedRiskDisposition:
    if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE:
        return (
            AdvancedRiskDisposition.REJECT
            if any(item.disposition is AdvancedRiskDisposition.REJECT for item in assessments)
            else AdvancedRiskDisposition.NONE
        )
    if any(item.disposition is AdvancedRiskDisposition.HALT for item in assessments):
        return AdvancedRiskDisposition.HALT
    if any(item.disposition is AdvancedRiskDisposition.PAUSE for item in assessments):
        return AdvancedRiskDisposition.PAUSE
    return AdvancedRiskDisposition.NONE


def aggregate_moderate_advanced_risk(
    rule_assessments: tuple[AdvancedRiskRuleAssessment, ...],
    *,
    assessed_at: datetime,
) -> AdvancedRiskPolicyAssessment:
    """Aggregate same-scope rule results for diagnostics.

    This low-level operation does not prove complete policy coverage.  Atomic
    admission must use :func:`assess_moderate_advanced_risk`.
    """

    if type(rule_assessments) is not tuple or not rule_assessments:
        raise AdvancedRiskPolicyError("advanced-risk aggregation requires a non-empty exact tuple")
    if any(type(item) is not AdvancedRiskRuleAssessment for item in rule_assessments):
        raise AdvancedRiskPolicyError("advanced-risk aggregation requires exact assessments")
    first = rule_assessments[0]
    ordered = tuple(
        sorted(rule_assessments, key=lambda item: (item.rule_id.value, item.subject_id))
    )
    return AdvancedRiskPolicyAssessment(
        account_id=first.account_id,
        environment=first.environment,
        policy_id=first.policy_id,
        policy_sha256=first.policy_sha256,
        mode=first.mode,
        rule_assessments=ordered,
        disposition=_aggregate_disposition(first.mode, ordered),
        assessed_at=assessed_at,
    )


def assess_moderate_advanced_risk(
    observations: tuple[AdvancedRiskPolicyObservation, ...],
    *,
    mode: AdvancedRiskEvaluationMode,
    required_instrument_ids: tuple[str, ...],
    assessed_at: datetime,
) -> AdvancedRiskPolicyAssessment:
    """Evaluate an exact all-applicable-rule evidence set.

    This result is necessary evidence only.  It deliberately has no
    ``authorized`` or policy-assignment claim.
    """

    if type(observations) is not tuple or not observations:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy assessment requires a non-empty exact tuple"
        )
    if any(type(item) is not AdvancedRiskPolicyObservation for item in observations):
        raise AdvancedRiskPolicyError("advanced-risk policy assessment requires exact observations")
    if type(mode) is not AdvancedRiskEvaluationMode:
        raise AdvancedRiskPolicyError("advanced-risk policy assessment mode is unsupported")
    if type(required_instrument_ids) is not tuple:
        raise AdvancedRiskPolicyError(
            "advanced-risk required instrument IDs must be an exact tuple"
        )
    if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE and not required_instrument_ids:
        raise AdvancedRiskPolicyError(
            "pretrade advanced-risk assessment requires a proposed instrument"
        )
    if required_instrument_ids != tuple(sorted(required_instrument_ids)) or len(
        required_instrument_ids
    ) != len(set(required_instrument_ids)):
        raise AdvancedRiskPolicyError(
            "advanced-risk required instrument IDs must be sorted and unique"
        )
    if any(
        type(instrument_id) is not str or instrument_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS
        for instrument_id in required_instrument_ids
    ):
        raise AdvancedRiskPolicyError(
            "advanced-risk required instrument ID is outside policy scope"
        )
    account_id = observations[0].account_id
    environment = observations[0].environment
    if any(
        item.account_id != account_id or item.environment != environment for item in observations
    ):
        raise AdvancedRiskPolicyConflict("advanced-risk policy observations have conflicting scope")
    identities = tuple((item.rule_id, item.subject_id) for item in observations)
    if len(identities) != len(set(identities)):
        raise AdvancedRiskPolicyConflict(
            "advanced-risk policy assessment repeats a rule and subject"
        )
    expected_identities: set[tuple[ModerateAdvancedRiskRuleId, str]] = set()
    for rule in MODERATE_ADVANCED_RISK_RULES:
        if not _mode_is_applicable(rule, mode):
            continue
        if rule.rule_id in _INSTRUMENT_SCOPED_RULES:
            expected_identities.update(
                (rule.rule_id, instrument_id) for instrument_id in required_instrument_ids
            )
        else:
            expected_identities.add((rule.rule_id, account_id))
    if set(identities) != expected_identities:
        raise AdvancedRiskPolicyConflict(
            "advanced-risk policy assessment requires exact applicable rule coverage"
        )
    expected_order = tuple(
        sorted(identities, key=lambda identity: (identity[0].value, identity[1]))
    )
    if identities != expected_order:
        raise AdvancedRiskPolicyError(
            "advanced-risk policy observations must be canonically ordered"
        )
    evaluated = tuple(
        evaluate_moderate_advanced_risk(item, mode=mode, assessed_at=assessed_at)
        for item in observations
    )
    return aggregate_moderate_advanced_risk(evaluated, assessed_at=assessed_at)
