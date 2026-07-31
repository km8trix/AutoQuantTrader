"""Pure authenticated metric producers for the fixed Phase 5B policy."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise

from packages.domain.advanced_risk import (
    MAX_ADVANCED_RISK_SOURCE_COUNT,
    MAX_ADVANCED_RISK_SOURCES,
    AdvancedRiskObservationCompleteness,
)
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_ENVIRONMENT,
    MODERATE_ADVANCED_RISK_INSTRUMENTS,
    MODERATE_ADVANCED_RISK_RULES,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskRule,
    ModerateAdvancedRiskRuleId,
    conservative_positive_risk_decimal,
)
from packages.domain.canonical import (
    canonical_json_bytes,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import (
    DECIMAL_ARITHMETIC_VERSION,
    deterministic_decimal_divide,
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.models import Side

ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION = "phase5b-advanced-risk-metrics-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SYMBOL_BY_INSTRUMENT = {
    "US-ETF-DIA": "DIA",
    "US-ETF-IWM": "IWM",
    "US-ETF-QQQ": "QQQ",
    "US-ETF-SPY": "SPY",
}
_RULE_BY_ID = {rule.rule_id: rule for rule in MODERATE_ADVANCED_RISK_RULES}


class AdvancedRiskMetricError(ValueError):
    """Authenticated metric evidence is malformed."""


class AdvancedRiskMetricConflict(AdvancedRiskMetricError):
    """Supposedly immutable metric facts conflict."""


class BrokerSubmissionOutcomeKind(StrEnum):
    ACCEPTED = "accepted"
    BUSINESS_REJECTED = "business_rejected"
    UNRESOLVED = "unresolved"
    EXCLUDED = "excluded"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _input_authority(label: str) -> str:
    return _sha256(
        (
            ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
            "authenticated_input_authority",
            label,
        )
    )


SESSION_EQUITY_INPUT_AUTHORITY_SHA256 = _input_authority("session_equity_chain_v1")
MINUTE_BAR_INPUT_AUTHORITY_SHA256 = _input_authority("admitted_rth_minute_bar_v1")
SIP_QUOTE_INPUT_AUTHORITY_SHA256 = _input_authority("entitled_consolidated_sip_quote_v1")
ADVERSE_MODEL_INPUT_AUTHORITY_SHA256 = _input_authority("adverse_execution_model_v1")
EXECUTION_FILL_INPUT_AUTHORITY_SHA256 = _input_authority(
    "applied_provider_execution_arrival_mid_v1"
)
BROKER_OUTCOME_INPUT_AUTHORITY_SHA256 = _input_authority("canonical_new_entry_broker_outcome_v1")
BROKER_REQUEST_INPUT_AUTHORITY_SHA256 = _input_authority("durable_broker_request_pressure_v1")
SCALAR_INPUT_AUTHORITY_SHA256 = _input_authority("durable_scalar_health_metric_v1")


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskMetricError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskMetricError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskMetricError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AdvancedRiskMetricError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise AdvancedRiskMetricError(f"{field_name} must be UTC")


def _decimal(value: Decimal, field_name: str, *, nonnegative: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise AdvancedRiskMetricError(f"{field_name} must be a finite exact Decimal")
    try:
        retained = canonical_persisted_decimal(value, field_name)
    except ValueError as error:
        raise AdvancedRiskMetricError(str(error)) from error
    if nonnegative and retained < 0:
        raise AdvancedRiskMetricError(f"{field_name} must be non-negative")
    return retained


def _instrument(instrument_id: str, symbol: str) -> None:
    if instrument_id not in MODERATE_ADVANCED_RISK_INSTRUMENTS:
        raise AdvancedRiskMetricError("metric instrument is outside the moderate policy")
    if symbol != _SYMBOL_BY_INSTRUMENT[instrument_id]:
        raise AdvancedRiskMetricConflict("metric instrument and symbol conflict")


def _microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _seconds_decimal(value: timedelta) -> Decimal:
    return _decimal(
        deterministic_decimal_divide(
            Decimal(_microseconds(value)),
            Decimal(1_000_000),
        ),
        "metric duration seconds",
        nonnegative=True,
    )


def _rule(rule_id: ModerateAdvancedRiskRuleId) -> ModerateAdvancedRiskRule:
    return _RULE_BY_ID[rule_id]


@dataclass(frozen=True, slots=True)
class AuthenticatedMetricSource:
    """One exact raw fact identity and availability boundary."""

    source_id: str
    source_sha256: str
    authority_sha256: str
    effective_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.source_id, "metric source ID")
        _require_sha256(self.source_sha256, "metric source_sha256")
        _require_sha256(self.authority_sha256, "metric source authority_sha256")
        _require_utc(self.effective_at, "metric source effective_at")
        _require_utc(self.available_at, "metric source available_at")
        if self.available_at < self.effective_at:
            raise AdvancedRiskMetricError(
                "metric source availability cannot precede effective time"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "authenticated_source",
                self.source_id,
                self.source_sha256,
                self.authority_sha256,
                self.effective_at,
                self.available_at,
            )
        )


def _source_set_sha256(
    rule_id: ModerateAdvancedRiskRuleId,
    sources: tuple[str, ...],
    source_count: int,
) -> str:
    return _sha256(
        (
            ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
            "metric_source_set",
            rule_id,
            source_count,
            sources,
        )
    )


def _combined_authority(
    expected: str,
    actual: tuple[str, ...],
    rule: ModerateAdvancedRiskRule,
) -> str:
    if all(value == expected for value in actual):
        return rule.source_authority_sha256
    return _sha256(
        (
            ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
            "untrusted_input_authorities",
            expected,
            actual,
        )
    )


def _project_signed(value: Decimal, field_name: str) -> Decimal:
    if value >= 0:
        return conservative_positive_risk_decimal(value, field_name)
    magnitude = value.copy_abs()
    sign, digits, raw_exponent = magnitude.as_tuple()
    assert sign == 0
    exponent = int(raw_exponent)
    if exponent >= -10:
        return _decimal(value, field_name)
    if len(digits) + exponent - 1 < -10:
        return Decimal(0)
    coefficient = int("".join(str(digit) for digit in digits))
    divisor = 10 ** (-10 - exponent)
    projected, _ = divmod(coefficient, divisor)
    projected_digits = tuple(int(character) for character in str(projected))
    return _decimal(Decimal((1, projected_digits, -10)), field_name)


def _make_observation(
    *,
    account_id: str,
    rule_id: ModerateAdvancedRiskRuleId,
    subject_id: str,
    source_authority_sha256: str,
    sources: tuple[str, ...],
    source_count: int,
    window_started_at: datetime,
    window_ended_at: datetime,
    observed_at: datetime,
    recorded_at: datetime,
    completeness: AdvancedRiskObservationCompleteness,
    value: Decimal | None,
    sample_count: int,
    qualifying_count: int | None = None,
    incomplete_reason: str | None = None,
    source_set_override_sha256: str | None = None,
) -> AdvancedRiskPolicyObservation:
    rule = _rule(rule_id)
    source_set_sha256 = (
        _source_set_sha256(rule_id, sources, source_count)
        if source_set_override_sha256 is None
        else source_set_override_sha256
    )
    evidence_sha256 = _sha256(
        (
            ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
            DECIMAL_ARITHMETIC_VERSION,
            "metric_observation_evidence",
            account_id,
            rule_id,
            subject_id,
            source_authority_sha256,
            source_count,
            sources,
            source_set_sha256,
            window_started_at,
            window_ended_at,
            observed_at,
            recorded_at,
            completeness,
            value,
            sample_count,
            qualifying_count,
            incomplete_reason,
        )
    )
    return AdvancedRiskPolicyObservation(
        account_id=account_id,
        environment=MODERATE_ADVANCED_RISK_ENVIRONMENT,
        rule_id=rule_id,
        subject_id=subject_id,
        completeness=completeness,
        value=value,
        sample_count=sample_count,
        qualifying_count=qualifying_count,
        producer_authority_sha256=rule.producer_authority_sha256,
        source_authority_sha256=source_authority_sha256,
        source_set_sha256=source_set_sha256,
        evidence_sha256=evidence_sha256,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        incomplete_reason=incomplete_reason,
    )


@dataclass(frozen=True, slots=True)
class AdvancedRiskMetricFailure:
    """Bounded incomplete source membership for any fixed policy metric."""

    account_id: str
    rule_id: ModerateAdvancedRiskRuleId
    subject_id: str
    source_authority_sha256: str
    completeness: AdvancedRiskObservationCompleteness
    retained_source_sha256s: tuple[str, ...]
    source_count: int
    full_source_set_sha256: str | None
    window_started_at: datetime
    window_ended_at: datetime
    observed_at: datetime
    recorded_at: datetime
    reason: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "metric failure account ID", maximum=64)
        if type(self.rule_id) is not ModerateAdvancedRiskRuleId:
            raise AdvancedRiskMetricError("metric failure rule is unsupported")
        _require_text(self.subject_id, "metric failure subject ID")
        _require_sha256(
            self.source_authority_sha256,
            "metric failure source_authority_sha256",
        )
        if self.completeness not in {
            AdvancedRiskObservationCompleteness.INSUFFICIENT,
            AdvancedRiskObservationCompleteness.UNAVAILABLE,
            AdvancedRiskObservationCompleteness.OVERFLOWED,
        }:
            raise AdvancedRiskMetricError("metric failure must be incomplete")
        if (
            type(self.retained_source_sha256s) is not tuple
            or len(self.retained_source_sha256s) > MAX_ADVANCED_RISK_SOURCES
        ):
            raise AdvancedRiskMetricError(
                "metric failure retained source membership exceeds its bound"
            )
        for source_sha256 in self.retained_source_sha256s:
            _require_sha256(source_sha256, "metric failure retained source digest")
        if len(self.retained_source_sha256s) != len(set(self.retained_source_sha256s)):
            raise AdvancedRiskMetricConflict("metric failure repeats a source digest")
        if self.retained_source_sha256s != tuple(sorted(self.retained_source_sha256s)):
            raise AdvancedRiskMetricError(
                "metric failure retained source digests must be canonical"
            )
        if (
            type(self.source_count) is not int
            or self.source_count < 0
            or self.source_count > MAX_ADVANCED_RISK_SOURCE_COUNT
        ):
            raise AdvancedRiskMetricError("metric failure source count is out of range")
        if self.completeness is AdvancedRiskObservationCompleteness.OVERFLOWED:
            if len(
                self.retained_source_sha256s
            ) != MAX_ADVANCED_RISK_SOURCES or self.source_count <= len(
                self.retained_source_sha256s
            ):
                raise AdvancedRiskMetricError(
                    "overflowed metric failure must retain its bounded prefix"
                )
            _require_sha256(
                self.full_source_set_sha256 or "",
                "metric failure full_source_set_sha256",
            )
        elif (
            self.source_count != len(self.retained_source_sha256s)
            or self.full_source_set_sha256 is not None
        ):
            raise AdvancedRiskMetricError(
                "non-overflowed metric failure source membership must be exact"
            )
        for instant, field_name in (
            (self.window_started_at, "metric failure window_started_at"),
            (self.window_ended_at, "metric failure window_ended_at"),
            (self.observed_at, "metric failure observed_at"),
            (self.recorded_at, "metric failure recorded_at"),
        ):
            _require_utc(instant, field_name)
        if not (
            self.window_started_at < self.window_ended_at
            and self.window_ended_at <= self.observed_at <= self.recorded_at
        ):
            raise AdvancedRiskMetricError("metric failure chronology is invalid")
        _require_text(self.reason, "metric failure reason", maximum=512)


def produce_metric_failure_observation(
    failure: AdvancedRiskMetricFailure,
) -> AdvancedRiskPolicyObservation:
    """Emit one typed incomplete observation without inventing a value."""

    if type(failure) is not AdvancedRiskMetricFailure:
        raise AdvancedRiskMetricError("metric failure must be exact")
    failure.__post_init__()
    return _make_observation(
        account_id=failure.account_id,
        rule_id=failure.rule_id,
        subject_id=failure.subject_id,
        source_authority_sha256=failure.source_authority_sha256,
        sources=failure.retained_source_sha256s,
        source_count=failure.source_count,
        source_set_override_sha256=(
            failure.full_source_set_sha256
            if failure.completeness is AdvancedRiskObservationCompleteness.OVERFLOWED
            else None
        ),
        window_started_at=failure.window_started_at,
        window_ended_at=failure.window_ended_at,
        observed_at=failure.observed_at,
        recorded_at=failure.recorded_at,
        completeness=failure.completeness,
        value=None,
        sample_count=failure.source_count,
        incomplete_reason=failure.reason,
    )


@dataclass(frozen=True, slots=True)
class SessionEquityPoint:
    account_id: str
    session_id: str
    sequence_number: int
    previous_point_sha256: str | None
    equity: Decimal
    cumulative_contributions: Decimal
    cumulative_withdrawals: Decimal
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _require_text(self.account_id, "session equity account ID", maximum=64)
        _require_text(self.session_id, "session equity session ID")
        if type(self.sequence_number) is not int or self.sequence_number < 0:
            raise AdvancedRiskMetricError("session equity sequence must be non-negative")
        if self.sequence_number == 0:
            if self.previous_point_sha256 is not None:
                raise AdvancedRiskMetricError(
                    "opening session equity point cannot have a predecessor"
                )
        else:
            _require_sha256(
                self.previous_point_sha256 or "",
                "session equity previous_point_sha256",
            )
        object.__setattr__(self, "equity", _decimal(self.equity, "session equity"))
        for field_name in (
            "cumulative_contributions",
            "cumulative_withdrawals",
        ):
            object.__setattr__(
                self,
                field_name,
                _decimal(
                    getattr(self, field_name),
                    f"session equity {field_name}",
                    nonnegative=True,
                ),
            )
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("session equity source must be exact")
        self.source.__post_init__()

    @property
    def adjusted_equity(self) -> Decimal:
        return exact_decimal_add(
            exact_decimal_subtract(self.equity, self.cumulative_contributions),
            self.cumulative_withdrawals,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "session_equity_point",
                self.account_id,
                self.session_id,
                self.sequence_number,
                self.previous_point_sha256,
                self.equity,
                self.cumulative_contributions,
                self.cumulative_withdrawals,
                self.source.semantic_sha256,
            )
        )


def produce_session_risk_observations(
    points: tuple[SessionEquityPoint, ...],
    *,
    session_opened_at: datetime,
    observed_at: datetime,
    recorded_at: datetime,
) -> tuple[AdvancedRiskPolicyObservation, AdvancedRiskPolicyObservation]:
    """Produce flow-adjusted session loss and durable high-water drawdown."""

    if (
        type(points) is not tuple
        or not points
        or any(type(point) is not SessionEquityPoint for point in points)
    ):
        raise AdvancedRiskMetricError("session risk requires a non-empty exact point tuple")
    for point in points:
        point.__post_init__()
    _require_utc(session_opened_at, "session opened_at")
    _require_utc(observed_at, "session observed_at")
    _require_utc(recorded_at, "session recorded_at")
    if not session_opened_at < observed_at <= recorded_at:
        raise AdvancedRiskMetricError("session risk chronology is invalid")
    account_id = points[0].account_id
    session_id = points[0].session_id
    for index, point in enumerate(points):
        if (
            point.account_id != account_id
            or point.session_id != session_id
            or point.sequence_number != index
            or point.source.effective_at < session_opened_at
            or point.source.effective_at > observed_at
            or point.source.available_at > observed_at
        ):
            raise AdvancedRiskMetricConflict(
                "session equity chain scope, sequence, or causality conflicts"
            )
        if index == 0:
            if point.source.effective_at != session_opened_at:
                raise AdvancedRiskMetricConflict(
                    "opening session equity point must bind the session open"
                )
        elif point.previous_point_sha256 != points[index - 1].semantic_sha256:
            raise AdvancedRiskMetricConflict("session equity chain has a gap")
        if index > 0 and (
            point.source.effective_at <= points[index - 1].source.effective_at
            or point.cumulative_contributions < points[index - 1].cumulative_contributions
            or point.cumulative_withdrawals < points[index - 1].cumulative_withdrawals
        ):
            raise AdvancedRiskMetricConflict(
                "session equity chronology or cumulative flows regress"
            )
    latest = points[-1]
    if points[0].cumulative_contributions != 0 or points[0].cumulative_withdrawals != 0:
        raise AdvancedRiskMetricConflict(
            "opening session equity point cannot include post-open cash flows"
        )
    if latest.source.effective_at <= session_opened_at:
        raise AdvancedRiskMetricError("session risk requires a post-open equity observation")
    sources = tuple(point.semantic_sha256 for point in points)
    authority_values = tuple(point.source.authority_sha256 for point in points)
    authority_ok = all(value == SESSION_EQUITY_INPUT_AUTHORITY_SHA256 for value in authority_values)
    complete = authority_ok and points[0].adjusted_equity > 0 and latest.adjusted_equity > 0
    completeness = (
        AdvancedRiskObservationCompleteness.COMPLETE
        if complete
        else AdvancedRiskObservationCompleteness.UNAVAILABLE
    )
    incomplete_reason = None if complete else "session equity authority or denominator unavailable"
    opening_equity = points[0].adjusted_equity
    current_equity = latest.adjusted_equity
    high_water = max(point.adjusted_equity for point in points)
    loss_numerator = max(Decimal(0), exact_decimal_subtract(opening_equity, current_equity))
    drawdown_numerator = max(
        Decimal(0),
        exact_decimal_subtract(high_water, current_equity),
    )

    def build(
        rule_id: ModerateAdvancedRiskRuleId,
        numerator: Decimal,
        denominator: Decimal,
    ) -> AdvancedRiskPolicyObservation:
        rule = _rule(rule_id)
        authority = _combined_authority(
            SESSION_EQUITY_INPUT_AUTHORITY_SHA256,
            authority_values,
            rule,
        )
        return _make_observation(
            account_id=account_id,
            rule_id=rule_id,
            subject_id=account_id,
            source_authority_sha256=authority,
            sources=sources,
            source_count=len(sources),
            window_started_at=session_opened_at,
            window_ended_at=latest.source.effective_at,
            observed_at=observed_at,
            recorded_at=recorded_at,
            completeness=completeness,
            value=(
                conservative_positive_risk_decimal(
                    deterministic_decimal_divide(numerator, denominator),
                    f"{rule_id.value} ratio",
                )
                if complete
                else None
            ),
            sample_count=len(points),
            incomplete_reason=incomplete_reason,
        )

    return (
        build(
            ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO,
            loss_numerator,
            opening_equity,
        ),
        build(
            ModerateAdvancedRiskRuleId.SESSION_DRAWDOWN_RATIO,
            drawdown_numerator,
            high_water,
        ),
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedMinuteBar:
    instrument_id: str
    symbol: str
    session_label: date
    interval_started_at: datetime
    interval_ended_at: datetime
    close_price: Decimal
    source_profile_sha256: str
    calendar_sha256: str
    security_master_sha256: str
    corporate_action_sha256: str
    watermark_sha256: str
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _instrument(self.instrument_id, self.symbol)
        if type(self.session_label) is not date:
            raise AdvancedRiskMetricError("minute bar session label must be a date")
        _require_utc(self.interval_started_at, "minute bar interval_started_at")
        _require_utc(self.interval_ended_at, "minute bar interval_ended_at")
        if self.interval_ended_at - self.interval_started_at != timedelta(minutes=1):
            raise AdvancedRiskMetricError("minute bar interval must be exactly one minute")
        close = _decimal(self.close_price, "minute bar close price")
        if close <= 0:
            raise AdvancedRiskMetricError("minute bar close price must be positive")
        object.__setattr__(self, "close_price", close)
        for value, field_name in (
            (self.source_profile_sha256, "minute bar source_profile_sha256"),
            (self.calendar_sha256, "minute bar calendar_sha256"),
            (self.security_master_sha256, "minute bar security_master_sha256"),
            (self.corporate_action_sha256, "minute bar corporate_action_sha256"),
            (self.watermark_sha256, "minute bar watermark_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("minute bar source must be exact")
        self.source.__post_init__()
        if self.source.effective_at != self.interval_ended_at:
            raise AdvancedRiskMetricConflict("minute bar source must be effective at interval end")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "minute_bar",
                self.instrument_id,
                self.symbol,
                self.session_label,
                self.interval_started_at,
                self.interval_ended_at,
                self.close_price,
                self.source_profile_sha256,
                self.calendar_sha256,
                self.security_master_sha256,
                self.corporate_action_sha256,
                self.watermark_sha256,
                self.source.semantic_sha256,
            )
        )


def produce_volatility_observation(
    *,
    account_id: str,
    instrument_id: str,
    bars: tuple[AuthenticatedMinuteBar, ...],
    session_opened_at: datetime,
    session_closed_at: datetime,
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce max absolute close-to-close return over 30 consecutive returns."""

    _require_text(account_id, "volatility account ID", maximum=64)
    _instrument(instrument_id, _SYMBOL_BY_INSTRUMENT.get(instrument_id, ""))
    for instant, field_name in (
        (session_opened_at, "volatility session_opened_at"),
        (session_closed_at, "volatility session_closed_at"),
        (observed_at, "volatility observed_at"),
        (recorded_at, "volatility recorded_at"),
    ):
        _require_utc(instant, field_name)
    if not session_opened_at < observed_at <= recorded_at or session_closed_at <= session_opened_at:
        raise AdvancedRiskMetricError("volatility chronology is invalid")
    if type(bars) is not tuple or any(type(bar) is not AuthenticatedMinuteBar for bar in bars):
        raise AdvancedRiskMetricError("volatility bars must be an exact tuple")
    if len(bars) > MAX_ADVANCED_RISK_SOURCES:
        raise AdvancedRiskMetricError("volatility source membership exceeds its bound")
    for bar in bars:
        bar.__post_init__()
    if bars != tuple(sorted(bars, key=lambda bar: bar.interval_started_at)):
        raise AdvancedRiskMetricError("volatility bars must be canonically ordered")
    selected = bars[-31:]
    sources = tuple(bar.semantic_sha256 for bar in selected)
    sample_count = max(0, len(selected) - 1)
    rule = _rule(ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO)
    authority_values = tuple(bar.source.authority_sha256 for bar in selected)
    authority = _combined_authority(
        MINUTE_BAR_INPUT_AUTHORITY_SHA256,
        authority_values,
        rule,
    )
    completeness = AdvancedRiskObservationCompleteness.COMPLETE
    incomplete_reason: str | None = None
    value: Decimal | None = None
    if len(selected) < 31:
        completeness = AdvancedRiskObservationCompleteness.INSUFFICIENT
        incomplete_reason = "fewer than 31 consecutive minute bars"
    elif any(
        bar.instrument_id != instrument_id
        or bar.source.available_at > observed_at
        or not (
            session_opened_at <= bar.interval_started_at
            and bar.interval_ended_at <= session_closed_at
        )
        for bar in selected
    ):
        completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
        incomplete_reason = "minute bar scope or causality is unavailable"
    else:
        shared_profiles = {
            (
                bar.session_label,
                bar.source_profile_sha256,
                bar.calendar_sha256,
                bar.security_master_sha256,
                bar.corporate_action_sha256,
                bar.watermark_sha256,
            )
            for bar in selected
        }
        consecutive = all(
            right.interval_started_at == left.interval_ended_at
            for left, right in pairwise(selected)
        )
        if (
            len(shared_profiles) != 1
            or not consecutive
            or any(
                authority_value != MINUTE_BAR_INPUT_AUTHORITY_SHA256
                for authority_value in authority_values
            )
        ):
            completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
            incomplete_reason = "minute bar continuity, version, or authority mismatch"
        else:
            returns = tuple(
                exact_decimal_subtract(
                    deterministic_decimal_divide(
                        current.close_price,
                        previous.close_price,
                    ),
                    Decimal(1),
                ).copy_abs()
                for previous, current in pairwise(selected)
            )
            value = conservative_positive_risk_decimal(
                max(returns),
                "volatility max absolute return",
            )
    window_start = selected[0].interval_started_at if selected else session_opened_at
    window_end = selected[-1].interval_ended_at if selected else observed_at
    return _make_observation(
        account_id=account_id,
        rule_id=rule.rule_id,
        subject_id=instrument_id,
        source_authority_sha256=authority,
        sources=sources,
        source_count=len(sources),
        window_started_at=window_start,
        window_ended_at=window_end,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=completeness,
        value=value,
        sample_count=sample_count,
        incomplete_reason=incomplete_reason,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedSipQuote:
    instrument_id: str
    symbol: str
    bid_price: Decimal
    ask_price: Decimal
    conditions_valid: bool
    feed_profile_sha256: str
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _instrument(self.instrument_id, self.symbol)
        bid = _decimal(self.bid_price, "SIP quote bid price")
        ask = _decimal(self.ask_price, "SIP quote ask price")
        if bid <= 0 or ask <= 0 or bid > ask:
            raise AdvancedRiskMetricError("SIP quote requires positive bid not greater than ask")
        object.__setattr__(self, "bid_price", bid)
        object.__setattr__(self, "ask_price", ask)
        if type(self.conditions_valid) is not bool:
            raise AdvancedRiskMetricError("SIP quote conditions_valid must be bool")
        _require_sha256(self.feed_profile_sha256, "SIP quote feed_profile_sha256")
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("SIP quote source must be exact")
        self.source.__post_init__()

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "sip_quote",
                self.instrument_id,
                self.symbol,
                self.bid_price,
                self.ask_price,
                self.conditions_valid,
                self.feed_profile_sha256,
                self.source.semantic_sha256,
            )
        )


def _quote_spread_bps(quote: AuthenticatedSipQuote) -> Decimal:
    midpoint = deterministic_decimal_divide(
        exact_decimal_add(quote.bid_price, quote.ask_price),
        Decimal(2),
    )
    spread = exact_decimal_subtract(quote.ask_price, quote.bid_price)
    return conservative_positive_risk_decimal(
        exact_decimal_multiply(
            deterministic_decimal_divide(spread, midpoint),
            Decimal(10_000),
        ),
        "SIP NBBO full spread bps",
    )


def _quote_available(
    quote: AuthenticatedSipQuote,
    *,
    session_opened_at: datetime,
    session_closed_at: datetime,
    observed_at: datetime,
) -> tuple[bool, str | None]:
    if quote.source.authority_sha256 != SIP_QUOTE_INPUT_AUTHORITY_SHA256:
        return False, "SIP quote authority mismatch"
    if not quote.conditions_valid:
        return False, "SIP quote conditions are unavailable"
    if not (
        session_opened_at < quote.source.effective_at < session_closed_at
        and quote.source.available_at <= observed_at
    ):
        return False, "SIP quote session or availability is invalid"
    if observed_at - quote.source.effective_at >= timedelta(
        seconds=5
    ) or observed_at - quote.source.available_at >= timedelta(seconds=5):
        return False, "SIP quote is stale"
    return True, None


def produce_spread_observation(
    *,
    account_id: str,
    quote: AuthenticatedSipQuote,
    session_opened_at: datetime,
    session_closed_at: datetime,
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce full consolidated spread with a strict sub-five-second source."""

    _require_text(account_id, "spread account ID", maximum=64)
    if type(quote) is not AuthenticatedSipQuote:
        raise AdvancedRiskMetricError("spread quote must be exact")
    quote.__post_init__()
    for instant, field_name in (
        (session_opened_at, "spread session_opened_at"),
        (session_closed_at, "spread session_closed_at"),
        (observed_at, "spread observed_at"),
        (recorded_at, "spread recorded_at"),
    ):
        _require_utc(instant, field_name)
    if not session_opened_at < observed_at <= recorded_at:
        raise AdvancedRiskMetricError("spread chronology is invalid")
    complete, reason = _quote_available(
        quote,
        session_opened_at=session_opened_at,
        session_closed_at=session_closed_at,
        observed_at=observed_at,
    )
    rule = _rule(ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS)
    authority = _combined_authority(
        SIP_QUOTE_INPUT_AUTHORITY_SHA256,
        (quote.source.authority_sha256,),
        rule,
    )
    return _make_observation(
        account_id=account_id,
        rule_id=rule.rule_id,
        subject_id=quote.instrument_id,
        source_authority_sha256=authority,
        sources=(quote.semantic_sha256,),
        source_count=1,
        window_started_at=session_opened_at,
        window_ended_at=quote.source.effective_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=(
            AdvancedRiskObservationCompleteness.COMPLETE
            if complete
            else AdvancedRiskObservationCompleteness.UNAVAILABLE
        ),
        value=_quote_spread_bps(quote) if complete else None,
        sample_count=1,
        incomplete_reason=reason,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedAdverseSlippageEstimate:
    instrument_id: str
    symbol: str
    adverse_bps: Decimal
    model_id: str
    model_version: str
    model_sha256: str
    excludes_spread: bool
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _instrument(self.instrument_id, self.symbol)
        object.__setattr__(
            self,
            "adverse_bps",
            _decimal(
                self.adverse_bps,
                "adverse slippage estimate bps",
                nonnegative=True,
            ),
        )
        _require_text(self.model_id, "adverse slippage model ID")
        _require_text(self.model_version, "adverse slippage model version")
        _require_sha256(self.model_sha256, "adverse slippage model_sha256")
        if self.excludes_spread is not True:
            raise AdvancedRiskMetricError(
                "adverse slippage estimate must explicitly exclude spread"
            )
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("adverse slippage source must be exact")
        self.source.__post_init__()

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "adverse_slippage_estimate",
                self.instrument_id,
                self.symbol,
                self.adverse_bps,
                self.model_id,
                self.model_version,
                self.model_sha256,
                self.excludes_spread,
                self.source.semantic_sha256,
            )
        )


def produce_projected_execution_cost_observation(
    *,
    account_id: str,
    quote: AuthenticatedSipQuote,
    estimate: AuthenticatedAdverseSlippageEstimate,
    session_opened_at: datetime,
    session_closed_at: datetime,
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce half-spread plus a separately versioned adverse estimate."""

    _require_text(account_id, "projected cost account ID", maximum=64)
    if (
        type(quote) is not AuthenticatedSipQuote
        or type(estimate) is not AuthenticatedAdverseSlippageEstimate
    ):
        raise AdvancedRiskMetricError("projected cost inputs must be exact")
    quote.__post_init__()
    estimate.__post_init__()
    if quote.instrument_id != estimate.instrument_id or quote.symbol != estimate.symbol:
        raise AdvancedRiskMetricConflict("projected cost quote and estimate instruments differ")
    for instant, field_name in (
        (session_opened_at, "projected cost session_opened_at"),
        (session_closed_at, "projected cost session_closed_at"),
        (observed_at, "projected cost observed_at"),
        (recorded_at, "projected cost recorded_at"),
    ):
        _require_utc(instant, field_name)
    quote_complete, reason = _quote_available(
        quote,
        session_opened_at=session_opened_at,
        session_closed_at=session_closed_at,
        observed_at=observed_at,
    )
    estimate_complete = (
        estimate.source.authority_sha256 == ADVERSE_MODEL_INPUT_AUTHORITY_SHA256
        and session_opened_at <= estimate.source.effective_at <= observed_at
        and estimate.source.available_at <= observed_at
    )
    complete = quote_complete and estimate_complete
    if reason is None and not estimate_complete:
        reason = "adverse slippage estimate authority or causality unavailable"
    rule = _rule(ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS)
    authorities = (
        quote.source.authority_sha256,
        estimate.source.authority_sha256,
    )
    expected_combined = _sha256(
        (
            SIP_QUOTE_INPUT_AUTHORITY_SHA256,
            ADVERSE_MODEL_INPUT_AUTHORITY_SHA256,
        )
    )
    actual_combined = _sha256(authorities)
    authority = (
        rule.source_authority_sha256
        if complete and actual_combined == expected_combined
        else _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "projected_cost_untrusted_authorities",
                authorities,
            )
        )
    )
    value = None
    if complete:
        value = conservative_positive_risk_decimal(
            exact_decimal_add(
                deterministic_decimal_divide(_quote_spread_bps(quote), Decimal(2)),
                estimate.adverse_bps,
            ),
            "projected execution cost bps",
        )
    return _make_observation(
        account_id=account_id,
        rule_id=rule.rule_id,
        subject_id=quote.instrument_id,
        source_authority_sha256=authority,
        sources=(quote.semantic_sha256, estimate.semantic_sha256),
        source_count=2,
        window_started_at=session_opened_at,
        window_ended_at=max(
            quote.source.effective_at,
            estimate.source.effective_at,
        ),
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=(
            AdvancedRiskObservationCompleteness.COMPLETE
            if complete
            else AdvancedRiskObservationCompleteness.UNAVAILABLE
        ),
        value=value,
        sample_count=2,
        incomplete_reason=reason,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutionFill:
    execution_id: str
    attempt_id: str
    instrument_id: str
    symbol: str
    side: Side
    quantity: Decimal
    fill_price: Decimal
    arrival_mid: Decimal
    dispatch_at: datetime
    arrival_quote_sha256: str
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _require_text(self.execution_id, "execution fill ID")
        _require_text(self.attempt_id, "execution fill attempt ID")
        _instrument(self.instrument_id, self.symbol)
        if type(self.side) is not Side:
            raise AdvancedRiskMetricError("execution fill side is unsupported")
        for field_name in ("quantity", "fill_price", "arrival_mid"):
            value = _decimal(getattr(self, field_name), f"execution fill {field_name}")
            if value <= 0:
                raise AdvancedRiskMetricError(f"execution fill {field_name} must be positive")
            object.__setattr__(self, field_name, value)
        _require_utc(self.dispatch_at, "execution fill dispatch_at")
        _require_sha256(
            self.arrival_quote_sha256,
            "execution fill arrival_quote_sha256",
        )
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("execution fill source must be exact")
        self.source.__post_init__()
        if not self.dispatch_at <= self.source.effective_at <= self.source.available_at:
            raise AdvancedRiskMetricError("execution fill chronology is invalid")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "execution_fill",
                self.execution_id,
                self.attempt_id,
                self.instrument_id,
                self.symbol,
                self.side,
                self.quantity,
                self.fill_price,
                self.arrival_mid,
                self.dispatch_at,
                self.arrival_quote_sha256,
                self.source.semantic_sha256,
            )
        )


def produce_realized_slippage_observation(
    *,
    account_id: str,
    fills: tuple[AuthenticatedExecutionFill, ...],
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce the latest exactly-20-fill notional-weighted adverse slippage."""

    _require_text(account_id, "realized slippage account ID", maximum=64)
    _require_utc(observed_at, "realized slippage observed_at")
    _require_utc(recorded_at, "realized slippage recorded_at")
    if observed_at > recorded_at:
        raise AdvancedRiskMetricError("realized slippage recording predates observation")
    if type(fills) is not tuple or any(
        type(fill) is not AuthenticatedExecutionFill for fill in fills
    ):
        raise AdvancedRiskMetricError("realized slippage fills must be exact")
    if len(fills) > MAX_ADVANCED_RISK_SOURCES:
        raise AdvancedRiskMetricError("realized slippage source membership exceeds its bound")
    for fill in fills:
        fill.__post_init__()
    if fills != tuple(
        sorted(
            fills,
            key=lambda fill: (fill.source.effective_at, fill.execution_id),
        )
    ):
        raise AdvancedRiskMetricError("realized slippage fills must be canonically ordered")
    execution_ids = tuple(fill.execution_id for fill in fills)
    if len(execution_ids) != len(set(execution_ids)):
        raise AdvancedRiskMetricConflict("realized slippage repeats an execution")
    cutoff = observed_at - timedelta(minutes=30)
    eligible = tuple(fill for fill in fills if cutoff < fill.source.effective_at <= observed_at)
    selected = eligible[-20:]
    sources = tuple(fill.semantic_sha256 for fill in selected)
    authority_values = tuple(fill.source.authority_sha256 for fill in selected)
    rule = _rule(ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS)
    authority = _combined_authority(
        EXECUTION_FILL_INPUT_AUTHORITY_SHA256,
        authority_values,
        rule,
    )
    completeness = AdvancedRiskObservationCompleteness.COMPLETE
    reason: str | None = None
    value: Decimal | None = None
    if len(selected) < 20:
        completeness = AdvancedRiskObservationCompleteness.INSUFFICIENT
        reason = "fewer than 20 eligible fills in the trailing window"
    elif any(
        fill.source.authority_sha256 != EXECUTION_FILL_INPUT_AUTHORITY_SHA256
        or fill.source.available_at > observed_at
        for fill in selected
    ):
        completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
        reason = "execution fill authority or availability mismatch"
    else:
        adverse_dollars = tuple(
            exact_decimal_multiply(
                exact_decimal_multiply(
                    Decimal(1) if fill.side is Side.BUY else Decimal(-1),
                    exact_decimal_subtract(fill.fill_price, fill.arrival_mid),
                ),
                fill.quantity,
            )
            for fill in selected
        )
        arrival_notionals = tuple(
            exact_decimal_multiply(fill.arrival_mid, fill.quantity) for fill in selected
        )
        value = _project_signed(
            exact_decimal_multiply(
                deterministic_decimal_divide(
                    exact_decimal_sum(adverse_dollars),
                    exact_decimal_sum(arrival_notionals),
                ),
                Decimal(10_000),
            ),
            "realized adverse slippage bps",
        )
    return _make_observation(
        account_id=account_id,
        rule_id=rule.rule_id,
        subject_id=account_id,
        source_authority_sha256=authority,
        sources=sources,
        source_count=len(sources),
        window_started_at=cutoff,
        window_ended_at=observed_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=completeness,
        value=value,
        sample_count=len(selected),
        incomplete_reason=reason,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedBrokerSubmissionOutcome:
    attempt_id: str
    attempt_sequence: int
    outcome: BrokerSubmissionOutcomeKind
    broker_code: str | None
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _require_text(self.attempt_id, "broker outcome attempt ID")
        if type(self.attempt_sequence) is not int or self.attempt_sequence < 1:
            raise AdvancedRiskMetricError("broker outcome attempt sequence must be positive")
        if type(self.outcome) is not BrokerSubmissionOutcomeKind:
            raise AdvancedRiskMetricError("broker submission outcome is unsupported")
        if self.outcome is BrokerSubmissionOutcomeKind.BUSINESS_REJECTED:
            _require_text(self.broker_code or "", "broker rejection code")
        elif self.broker_code is not None:
            raise AdvancedRiskMetricError("only a business rejection may carry a broker code")
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("broker outcome source must be exact")
        self.source.__post_init__()

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "broker_submission_outcome",
                self.attempt_id,
                self.attempt_sequence,
                self.outcome,
                self.broker_code,
                self.source.semantic_sha256,
            )
        )


def produce_broker_reject_observations(
    *,
    account_id: str,
    outcomes: tuple[AuthenticatedBrokerSubmissionOutcome, ...],
    observed_at: datetime,
    recorded_at: datetime,
) -> tuple[AdvancedRiskPolicyObservation, AdvancedRiskPolicyObservation]:
    """Produce definitive reject rate and the non-bridging reject suffix."""

    _require_text(account_id, "broker reject account ID", maximum=64)
    _require_utc(observed_at, "broker reject observed_at")
    _require_utc(recorded_at, "broker reject recorded_at")
    if observed_at > recorded_at:
        raise AdvancedRiskMetricError("broker reject recording predates observation")
    if type(outcomes) is not tuple or any(
        type(outcome) is not AuthenticatedBrokerSubmissionOutcome for outcome in outcomes
    ):
        raise AdvancedRiskMetricError("broker reject outcomes must be exact")
    if len(outcomes) > MAX_ADVANCED_RISK_SOURCES:
        raise AdvancedRiskMetricError("broker reject source membership exceeds its bound")
    for outcome in outcomes:
        outcome.__post_init__()
    expected = tuple(
        sorted(
            outcomes,
            key=lambda outcome: (
                outcome.attempt_sequence,
                outcome.attempt_id,
            ),
        )
    )
    if outcomes != expected:
        raise AdvancedRiskMetricError("broker reject outcomes must be canonically ordered")
    attempt_ids = tuple(outcome.attempt_id for outcome in outcomes)
    sequences = tuple(outcome.attempt_sequence for outcome in outcomes)
    if len(attempt_ids) != len(set(attempt_ids)) or len(sequences) != len(set(sequences)):
        raise AdvancedRiskMetricConflict(
            "broker reject outcomes repeat an attempt identity or sequence"
        )
    cutoff = observed_at - timedelta(minutes=10)
    eligible = tuple(
        outcome
        for outcome in outcomes
        if cutoff < outcome.source.effective_at <= observed_at
        and outcome.outcome is not BrokerSubmissionOutcomeKind.EXCLUDED
    )
    sources = tuple(outcome.semantic_sha256 for outcome in eligible)
    authority_values = tuple(outcome.source.authority_sha256 for outcome in eligible)
    authority_ok = all(
        value == BROKER_OUTCOME_INPUT_AUTHORITY_SHA256 for value in authority_values
    ) and all(outcome.source.available_at <= observed_at for outcome in eligible)
    definitive = tuple(
        outcome
        for outcome in eligible
        if outcome.outcome
        in {
            BrokerSubmissionOutcomeKind.ACCEPTED,
            BrokerSubmissionOutcomeKind.BUSINESS_REJECTED,
        }
    )
    rejected_count = sum(
        outcome.outcome is BrokerSubmissionOutcomeKind.BUSINESS_REJECTED for outcome in definitive
    )
    rate_rule = _rule(ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO)
    rate_authority = _combined_authority(
        BROKER_OUTCOME_INPUT_AUTHORITY_SHA256,
        authority_values,
        rate_rule,
    )
    if not authority_ok:
        rate_completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
        rate_reason = "broker outcome authority or availability mismatch"
        rate_value = None
    elif len(definitive) < 10:
        rate_completeness = AdvancedRiskObservationCompleteness.INSUFFICIENT
        rate_reason = "fewer than 10 definitive outcomes"
        rate_value = None
    else:
        rate_completeness = AdvancedRiskObservationCompleteness.COMPLETE
        rate_reason = None
        rate_value = conservative_positive_risk_decimal(
            deterministic_decimal_divide(
                Decimal(rejected_count),
                Decimal(len(definitive)),
            ),
            "broker reject rate ratio",
        )
    rate_observation = _make_observation(
        account_id=account_id,
        rule_id=rate_rule.rule_id,
        subject_id=account_id,
        source_authority_sha256=rate_authority,
        sources=sources,
        source_count=len(sources),
        window_started_at=cutoff,
        window_ended_at=observed_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=rate_completeness,
        value=rate_value,
        sample_count=len(definitive),
        qualifying_count=rejected_count,
        incomplete_reason=rate_reason,
    )

    consecutive_rule = _rule(ModerateAdvancedRiskRuleId.BROKER_CONSECUTIVE_REJECTS)
    consecutive_authority = _combined_authority(
        BROKER_OUTCOME_INPUT_AUTHORITY_SHA256,
        authority_values,
        consecutive_rule,
    )
    if not authority_ok:
        consecutive_completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
        consecutive_reason = "broker outcome authority or availability mismatch"
        consecutive_value = None
    elif not eligible:
        consecutive_completeness = AdvancedRiskObservationCompleteness.INSUFFICIENT
        consecutive_reason = "no eligible broker outcomes"
        consecutive_value = None
    elif eligible[-1].outcome is BrokerSubmissionOutcomeKind.UNRESOLVED:
        consecutive_completeness = AdvancedRiskObservationCompleteness.UNAVAILABLE
        consecutive_reason = "latest broker attempt remains unresolved"
        consecutive_value = None
    else:
        suffix = 0
        for outcome in reversed(eligible):
            if outcome.outcome is BrokerSubmissionOutcomeKind.BUSINESS_REJECTED:
                suffix += 1
                continue
            break
        consecutive_completeness = AdvancedRiskObservationCompleteness.COMPLETE
        consecutive_reason = None
        consecutive_value = Decimal(suffix)
    consecutive_observation = _make_observation(
        account_id=account_id,
        rule_id=consecutive_rule.rule_id,
        subject_id=account_id,
        source_authority_sha256=consecutive_authority,
        sources=sources,
        source_count=len(sources),
        window_started_at=cutoff,
        window_ended_at=observed_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=consecutive_completeness,
        value=consecutive_value,
        sample_count=len(eligible),
        incomplete_reason=consecutive_reason,
    )
    return rate_observation, consecutive_observation


@dataclass(frozen=True, slots=True)
class AuthenticatedBrokerRequestPressure:
    account_id: str
    current_request_count: int
    proposed_new_entry_count: int
    window_started_at: datetime
    window_ended_at: datetime
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _require_text(self.account_id, "broker request account ID", maximum=64)
        for field_name in (
            "current_request_count",
            "proposed_new_entry_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise AdvancedRiskMetricError(f"broker request {field_name} must be non-negative")
        _require_utc(self.window_started_at, "broker request window_started_at")
        _require_utc(self.window_ended_at, "broker request window_ended_at")
        if self.window_started_at >= self.window_ended_at:
            raise AdvancedRiskMetricError("broker request window must be non-empty")
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("broker request source must be exact")
        self.source.__post_init__()
        if not (self.window_started_at < self.source.effective_at <= self.window_ended_at):
            raise AdvancedRiskMetricConflict(
                "broker request source lies outside its trailing window"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "broker_request_pressure",
                self.account_id,
                self.current_request_count,
                self.proposed_new_entry_count,
                self.window_started_at,
                self.window_ended_at,
                self.source.semantic_sha256,
            )
        )


def produce_broker_request_observation(
    pressure: AuthenticatedBrokerRequestPressure,
    *,
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce current plus proposed request pressure exactly once."""

    if type(pressure) is not AuthenticatedBrokerRequestPressure:
        raise AdvancedRiskMetricError("broker request pressure must be exact")
    pressure.__post_init__()
    _require_utc(observed_at, "broker request observed_at")
    _require_utc(recorded_at, "broker request recorded_at")
    if (
        pressure.window_ended_at > observed_at
        or pressure.source.available_at > observed_at
        or observed_at > recorded_at
    ):
        raise AdvancedRiskMetricError("broker request chronology is not causal")
    rule = _rule(ModerateAdvancedRiskRuleId.BROKER_REQUEST_PROJECTED_COUNT)
    authority_values = (pressure.source.authority_sha256,)
    authority = _combined_authority(
        BROKER_REQUEST_INPUT_AUTHORITY_SHA256,
        authority_values,
        rule,
    )
    authority_ok = pressure.source.authority_sha256 == BROKER_REQUEST_INPUT_AUTHORITY_SHA256
    return _make_observation(
        account_id=pressure.account_id,
        rule_id=rule.rule_id,
        subject_id=pressure.account_id,
        source_authority_sha256=authority,
        sources=(pressure.semantic_sha256,),
        source_count=1,
        window_started_at=pressure.window_started_at,
        window_ended_at=pressure.window_ended_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=(
            AdvancedRiskObservationCompleteness.COMPLETE
            if authority_ok
            else AdvancedRiskObservationCompleteness.UNAVAILABLE
        ),
        value=(
            Decimal(pressure.current_request_count + pressure.proposed_new_entry_count)
            if authority_ok
            else None
        ),
        sample_count=pressure.current_request_count,
        incomplete_reason=(None if authority_ok else "broker request source authority mismatch"),
    )


_SCALAR_RULE_IDS = {
    ModerateAdvancedRiskRuleId.CLOCK_DRIFT_MILLISECONDS,
    ModerateAdvancedRiskRuleId.MARKET_DATA_AGE_SECONDS,
    ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
    ModerateAdvancedRiskRuleId.UNKNOWN_SUBMISSION_DURATION_SECONDS,
    ModerateAdvancedRiskRuleId.RECONCILIATION_DURATION_SECONDS,
}
_INTEGRAL_SCALAR_RULE_IDS = {
    ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
}


@dataclass(frozen=True, slots=True)
class AuthenticatedScalarMetric:
    account_id: str
    rule_id: ModerateAdvancedRiskRuleId
    value: Decimal
    window_started_at: datetime
    window_ended_at: datetime
    source: AuthenticatedMetricSource

    def __post_init__(self) -> None:
        _require_text(self.account_id, "scalar metric account ID", maximum=64)
        if (
            type(self.rule_id) is not ModerateAdvancedRiskRuleId
            or self.rule_id not in _SCALAR_RULE_IDS
        ):
            raise AdvancedRiskMetricError("scalar metric rule is unsupported")
        value = _decimal(self.value, "scalar metric value", nonnegative=True)
        if self.rule_id in _INTEGRAL_SCALAR_RULE_IDS and value != value.to_integral_value():
            raise AdvancedRiskMetricError("scalar count/binary metric must be integral")
        if self.rule_id is ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY and value not in {
            Decimal(0),
            Decimal(1),
        }:
            raise AdvancedRiskMetricError("data health metric must be binary")
        object.__setattr__(self, "value", value)
        _require_utc(self.window_started_at, "scalar metric window_started_at")
        _require_utc(self.window_ended_at, "scalar metric window_ended_at")
        if self.window_started_at >= self.window_ended_at:
            raise AdvancedRiskMetricError("scalar metric window must be non-empty")
        if type(self.source) is not AuthenticatedMetricSource:
            raise AdvancedRiskMetricError("scalar metric source must be exact")
        self.source.__post_init__()
        if not (self.window_started_at < self.source.effective_at <= self.window_ended_at):
            raise AdvancedRiskMetricConflict(
                "scalar source lies outside its open-left/closed-right window"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_RISK_METRIC_SOURCE_CONTRACT_VERSION,
                "scalar_metric",
                self.account_id,
                self.rule_id,
                self.value,
                self.window_started_at,
                self.window_ended_at,
                self.source.semantic_sha256,
            )
        )


def produce_scalar_metric_observation(
    metric: AuthenticatedScalarMetric,
    *,
    observed_at: datetime,
    recorded_at: datetime,
) -> AdvancedRiskPolicyObservation:
    """Produce request, clock/data health, UNKNOWN, or reconciliation evidence."""

    if type(metric) is not AuthenticatedScalarMetric:
        raise AdvancedRiskMetricError("scalar metric must be exact")
    metric.__post_init__()
    _require_utc(observed_at, "scalar metric observed_at")
    _require_utc(recorded_at, "scalar metric recorded_at")
    if (
        metric.window_ended_at > observed_at
        or metric.source.available_at > observed_at
        or observed_at > recorded_at
    ):
        raise AdvancedRiskMetricError("scalar metric chronology is not causal")
    rule = _rule(metric.rule_id)
    authority = _combined_authority(
        SCALAR_INPUT_AUTHORITY_SHA256,
        (metric.source.authority_sha256,),
        rule,
    )
    authority_ok = metric.source.authority_sha256 == SCALAR_INPUT_AUTHORITY_SHA256
    return _make_observation(
        account_id=metric.account_id,
        rule_id=metric.rule_id,
        subject_id=metric.account_id,
        source_authority_sha256=authority,
        sources=(metric.semantic_sha256,),
        source_count=1,
        window_started_at=metric.window_started_at,
        window_ended_at=metric.window_ended_at,
        observed_at=observed_at,
        recorded_at=recorded_at,
        completeness=(
            AdvancedRiskObservationCompleteness.COMPLETE
            if authority_ok
            else AdvancedRiskObservationCompleteness.UNAVAILABLE
        ),
        value=metric.value if authority_ok else None,
        sample_count=1,
        incomplete_reason=None if authority_ok else "scalar source authority mismatch",
    )
