from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from typing import Any

import pytest

from packages.domain.advanced_risk import AdvancedRiskObservationCompleteness
from packages.domain.advanced_risk_policy import (
    ADVANCED_RISK_POLICY_CONTRACT_VERSION,
    ADVANCED_RISK_POSITIVE_PROJECTION,
    MODERATE_ADVANCED_RISK_INSTRUMENTS,
    MODERATE_ADVANCED_RISK_POLICY,
    MODERATE_ADVANCED_RISK_POLICY_ID,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    MODERATE_ADVANCED_RISK_RULES,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyConflict,
    AdvancedRiskPolicyError,
    AdvancedRiskPolicyObservation,
    AdvancedRiskRuleAssessment,
    AdvancedRiskThresholdComparator,
    ModerateAdvancedRiskRule,
    ModerateAdvancedRiskRuleId,
    aggregate_moderate_advanced_risk,
    assess_moderate_advanced_risk,
    conservative_positive_risk_decimal,
    evaluate_moderate_advanced_risk,
)

NOW = datetime(2026, 7, 28, 15, 30, tzinfo=UTC)
ACCOUNT_ID = "paper-account"
INSTRUMENT_ID = "US-ETF-SPY"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def policy_rule(rule_id: ModerateAdvancedRiskRuleId) -> ModerateAdvancedRiskRule:
    return next(rule for rule in MODERATE_ADVANCED_RISK_RULES if rule.rule_id is rule_id)


def observation(
    rule_id: ModerateAdvancedRiskRuleId,
    *,
    value: Decimal | None = Decimal("0"),
    completeness: AdvancedRiskObservationCompleteness = (
        AdvancedRiskObservationCompleteness.COMPLETE
    ),
    sample_count: int | None = None,
    qualifying_count: int | None = None,
    subject_id: str | None = None,
    producer_authority_sha256: str | None = None,
    source_authority_sha256: str | None = None,
) -> AdvancedRiskPolicyObservation:
    rule = policy_rule(rule_id)
    if sample_count is None:
        sample_count = rule.minimum_complete_samples
    if rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO:
        qualifying_count = 3 if qualifying_count is None else qualifying_count
    if completeness is not AdvancedRiskObservationCompleteness.COMPLETE:
        value = None
    if subject_id is None:
        subject_id = (
            INSTRUMENT_ID
            if rule.measurement_scope.startswith("instrument")
            or rule.measurement_scope.startswith("proposed_instrument")
            else ACCOUNT_ID
        )
    return AdvancedRiskPolicyObservation(
        account_id=ACCOUNT_ID,
        environment="paper",
        rule_id=rule_id,
        subject_id=subject_id,
        completeness=completeness,
        value=value,
        sample_count=sample_count,
        qualifying_count=qualifying_count,
        producer_authority_sha256=(
            rule.producer_authority_sha256
            if producer_authority_sha256 is None
            else producer_authority_sha256
        ),
        source_authority_sha256=(
            rule.source_authority_sha256
            if source_authority_sha256 is None
            else source_authority_sha256
        ),
        source_set_sha256=digest(f"{rule_id.value}-sources"),
        evidence_sha256=digest(f"{rule_id.value}-evidence"),
        window_started_at=NOW - timedelta(minutes=30),
        window_ended_at=NOW - timedelta(seconds=1),
        observed_at=NOW,
        recorded_at=NOW + timedelta(seconds=1),
        incomplete_reason=(
            None
            if completeness is AdvancedRiskObservationCompleteness.COMPLETE
            else "producer could not complete the required source set"
        ),
    )


def evaluate(
    rule_id: ModerateAdvancedRiskRuleId,
    value: Decimal,
    mode: AdvancedRiskEvaluationMode,
    **kwargs: Any,
) -> AdvancedRiskRuleAssessment:
    return evaluate_moderate_advanced_risk(
        observation(rule_id, value=value, **kwargs),
        mode=mode,
        assessed_at=NOW + timedelta(seconds=2),
    )


def test_fixed_policy_scope_rules_and_digest_are_pinned() -> None:
    assert ADVANCED_RISK_POLICY_CONTRACT_VERSION == "phase5b-advanced-risk-policy-v1"
    assert ADVANCED_RISK_POSITIVE_PROJECTION == "ceiling-to-numeric-28-10-v1"
    assert MODERATE_ADVANCED_RISK_POLICY_ID == "phase5b-moderate-paper-rth-etf-v1"
    assert MODERATE_ADVANCED_RISK_INSTRUMENTS == (
        "US-ETF-DIA",
        "US-ETF-IWM",
        "US-ETF-QQQ",
        "US-ETF-SPY",
    )
    assert MODERATE_ADVANCED_RISK_POLICY.environment == "paper"
    assert MODERATE_ADVANCED_RISK_POLICY.market_session == "us_equities_rth"
    assert MODERATE_ADVANCED_RISK_POLICY.position_scope == "long_only"
    assert tuple(rule.rule_id for rule in MODERATE_ADVANCED_RISK_RULES) == tuple(
        ModerateAdvancedRiskRuleId
    )
    assert (
        MODERATE_ADVANCED_RISK_POLICY_SHA256
        == "58d38d8bcd1bfe43a7d9d10fed9c067501be5151f3818ef3408e177a3f1e81a5"
    )
    assert "authenticated" not in {field.name for field in fields(MODERATE_ADVANCED_RISK_POLICY)}
    assert "assigned" not in {field.name for field in fields(MODERATE_ADVANCED_RISK_POLICY)}


def test_exact_threshold_matrix_matches_the_approved_moderate_envelope() -> None:
    expected = {
        ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO: (
            None,
            Decimal("0.02"),
            Decimal("0.03"),
        ),
        ModerateAdvancedRiskRuleId.SESSION_DRAWDOWN_RATIO: (
            None,
            Decimal("0.025"),
            Decimal("0.04"),
        ),
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO: (
            Decimal("0.35"),
            Decimal("0.35"),
            Decimal("0.50"),
        ),
        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE: (
            Decimal("1.00"),
            Decimal("1.00"),
            Decimal("1.10"),
        ),
        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE: (
            Decimal("1.00"),
            Decimal("1.00"),
            Decimal("1.10"),
        ),
        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY: (
            Decimal("0"),
            Decimal("0"),
            Decimal("0"),
        ),
        ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO: (
            Decimal("0.015"),
            Decimal("0.015"),
            Decimal("0.03"),
        ),
        ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS: (
            Decimal("20"),
            Decimal("20"),
            Decimal("50"),
        ),
        ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS: (
            Decimal("25"),
            None,
            None,
        ),
        ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS: (
            None,
            Decimal("15"),
            Decimal("30"),
        ),
        ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO: (
            None,
            Decimal("0.10"),
            Decimal("0.25"),
        ),
        ModerateAdvancedRiskRuleId.BROKER_CONSECUTIVE_REJECTS: (
            None,
            Decimal("3"),
            Decimal("5"),
        ),
        ModerateAdvancedRiskRuleId.BROKER_REQUEST_PROJECTED_COUNT: (
            Decimal("160"),
            Decimal("180"),
            Decimal("200"),
        ),
        ModerateAdvancedRiskRuleId.CLOCK_DRIFT_MILLISECONDS: (
            Decimal("1000"),
            Decimal("1000"),
            None,
        ),
        ModerateAdvancedRiskRuleId.MARKET_DATA_AGE_SECONDS: (
            Decimal("15"),
            Decimal("15"),
            None,
        ),
        ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY: (
            Decimal("0"),
            Decimal("0"),
            None,
        ),
        ModerateAdvancedRiskRuleId.UNKNOWN_SUBMISSION_DURATION_SECONDS: (
            Decimal("60"),
            Decimal("60"),
            None,
        ),
        ModerateAdvancedRiskRuleId.RECONCILIATION_DURATION_SECONDS: (
            Decimal("120"),
            Decimal("120"),
            None,
        ),
    }
    assert {
        rule.rule_id: (
            rule.pretrade_reject_threshold,
            rule.runtime_pause_threshold,
            rule.runtime_halt_threshold,
        )
        for rule in MODERATE_ADVANCED_RISK_RULES
    } == expected


@pytest.mark.parametrize(
    "rule",
    tuple(
        item
        for item in MODERATE_ADVANCED_RISK_RULES
        if item.comparator is AdvancedRiskThresholdComparator.STRICTLY_GREATER
    ),
)
def test_strict_threshold_equality_passes_and_only_greater_breaches(
    rule: ModerateAdvancedRiskRule,
) -> None:
    increment = Decimal("0.0000000001")
    if rule.pretrade_reject_threshold is not None:
        at_limit = evaluate(
            rule.rule_id,
            rule.pretrade_reject_threshold,
            AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        )
        above_limit = evaluate(
            rule.rule_id,
            rule.pretrade_reject_threshold + increment,
            AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        )
        assert at_limit.disposition is AdvancedRiskDisposition.NONE
        assert above_limit.disposition is AdvancedRiskDisposition.REJECT
        assert above_limit.requires_control_trip is False
    if rule.runtime_pause_threshold is not None:
        at_pause = evaluate(
            rule.rule_id,
            rule.runtime_pause_threshold,
            AdvancedRiskEvaluationMode.RUNTIME,
        )
        above_pause = evaluate(
            rule.rule_id,
            rule.runtime_pause_threshold + increment,
            AdvancedRiskEvaluationMode.RUNTIME,
        )
        assert at_pause.disposition is AdvancedRiskDisposition.NONE
        assert above_pause.disposition is (
            AdvancedRiskDisposition.HALT
            if rule.runtime_halt_threshold == rule.runtime_pause_threshold
            else AdvancedRiskDisposition.PAUSE
        )
        assert above_pause.requires_control_trip is True
    if rule.runtime_halt_threshold is not None:
        at_halt = evaluate(
            rule.rule_id,
            rule.runtime_halt_threshold,
            AdvancedRiskEvaluationMode.RUNTIME,
            qualifying_count=5
            if rule.rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO
            else None,
        )
        above_halt = evaluate(
            rule.rule_id,
            rule.runtime_halt_threshold + increment,
            AdvancedRiskEvaluationMode.RUNTIME,
            qualifying_count=5
            if rule.rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO
            else None,
        )
        assert at_halt.disposition is (
            AdvancedRiskDisposition.NONE
            if rule.runtime_halt_threshold == rule.runtime_pause_threshold
            else AdvancedRiskDisposition.PAUSE
        )
        assert above_halt.disposition is AdvancedRiskDisposition.HALT


def test_consecutive_reject_count_has_explicit_at_least_exception() -> None:
    rule_id = ModerateAdvancedRiskRuleId.BROKER_CONSECUTIVE_REJECTS

    assert policy_rule(rule_id).comparator is AdvancedRiskThresholdComparator.AT_LEAST
    assert (
        evaluate(rule_id, Decimal("2"), AdvancedRiskEvaluationMode.RUNTIME).disposition
        is AdvancedRiskDisposition.NONE
    )
    assert (
        evaluate(rule_id, Decimal("3"), AdvancedRiskEvaluationMode.RUNTIME).disposition
        is AdvancedRiskDisposition.PAUSE
    )
    assert (
        evaluate(rule_id, Decimal("5"), AdvancedRiskEvaluationMode.RUNTIME).disposition
        is AdvancedRiskDisposition.HALT
    )


def test_cash_account_integrity_failure_rejects_pretrade_and_halts_runtime() -> None:
    rule_id = ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY

    assert (
        evaluate(
            rule_id,
            Decimal("1"),
            AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        ).disposition
        is AdvancedRiskDisposition.REJECT
    )
    runtime = evaluate(
        rule_id,
        Decimal("1"),
        AdvancedRiskEvaluationMode.RUNTIME,
    )
    assert runtime.disposition is AdvancedRiskDisposition.HALT
    assert runtime.requires_control_trip is True


def test_reject_rate_requires_both_ratio_and_reject_count() -> None:
    rule_id = ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO

    assert (
        evaluate(
            rule_id,
            Decimal("0.26"),
            AdvancedRiskEvaluationMode.RUNTIME,
            sample_count=10,
            qualifying_count=4,
        ).disposition
        is AdvancedRiskDisposition.PAUSE
    )
    assert (
        evaluate(
            rule_id,
            Decimal("0.26"),
            AdvancedRiskEvaluationMode.RUNTIME,
            sample_count=10,
            qualifying_count=5,
        ).disposition
        is AdvancedRiskDisposition.HALT
    )
    assert (
        evaluate(
            rule_id,
            Decimal("0.11"),
            AdvancedRiskEvaluationMode.RUNTIME,
            sample_count=10,
            qualifying_count=2,
        ).disposition
        is AdvancedRiskDisposition.NONE
    )


@pytest.mark.parametrize(
    ("rule_id", "sample_count"),
    (
        (ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS, 19),
        (ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO, 9),
    ),
)
def test_only_approved_sample_minimum_insufficiency_has_no_action(
    rule_id: ModerateAdvancedRiskRuleId,
    sample_count: int,
) -> None:
    result = evaluate_moderate_advanced_risk(
        observation(
            rule_id,
            completeness=AdvancedRiskObservationCompleteness.INSUFFICIENT,
            sample_count=sample_count,
            qualifying_count=0
            if rule_id is ModerateAdvancedRiskRuleId.BROKER_REJECT_RATE_RATIO
            else None,
        ),
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        assessed_at=NOW + timedelta(seconds=2),
    )

    assert result.disposition is AdvancedRiskDisposition.NONE
    assert result.reason_code == "sample_minimum_not_met_no_action"


@pytest.mark.parametrize(
    "completeness",
    (
        AdvancedRiskObservationCompleteness.INSUFFICIENT,
        AdvancedRiskObservationCompleteness.UNAVAILABLE,
        AdvancedRiskObservationCompleteness.OVERFLOWED,
    ),
)
@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        (
            AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            AdvancedRiskDisposition.REJECT,
        ),
        (AdvancedRiskEvaluationMode.RUNTIME, AdvancedRiskDisposition.PAUSE),
    ),
)
def test_incomplete_applicable_evidence_fails_closed_by_mode(
    completeness: AdvancedRiskObservationCompleteness,
    mode: AdvancedRiskEvaluationMode,
    expected: AdvancedRiskDisposition,
) -> None:
    result = evaluate_moderate_advanced_risk(
        observation(
            ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
            completeness=completeness,
            sample_count=0,
        ),
        mode=mode,
        assessed_at=NOW + timedelta(seconds=2),
    )

    assert result.disposition is expected
    assert result.requires_control_trip is (mode is AdvancedRiskEvaluationMode.RUNTIME)


def test_untrusted_authority_is_retained_and_downgraded_not_upgraded() -> None:
    supplied = digest("untrusted-source-authority")
    result = evaluate_moderate_advanced_risk(
        observation(
            ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
            value=Decimal("0"),
            source_authority_sha256=supplied,
        ),
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        assessed_at=NOW + timedelta(seconds=2),
    )

    assert result.input_completeness is AdvancedRiskObservationCompleteness.COMPLETE
    assert result.effective_completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE
    assert result.source_authority_sha256 == supplied
    assert result.disposition is AdvancedRiskDisposition.REJECT
    assert result.reason_code == "authority_mismatch"


def test_sample_contracts_are_downgraded_and_fail_closed() -> None:
    too_many_realized = evaluate_moderate_advanced_risk(
        observation(
            ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS,
            value=Decimal("1"),
            sample_count=21,
        ),
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        assessed_at=NOW + timedelta(seconds=2),
    )
    too_few_volatility = evaluate_moderate_advanced_risk(
        observation(
            ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
            value=Decimal("0.001"),
            sample_count=29,
        ),
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        assessed_at=NOW + timedelta(seconds=2),
    )

    assert too_many_realized.effective_completeness is (
        AdvancedRiskObservationCompleteness.UNAVAILABLE
    )
    assert too_many_realized.disposition is AdvancedRiskDisposition.PAUSE
    assert too_few_volatility.effective_completeness is (
        AdvancedRiskObservationCompleteness.INSUFFICIENT
    )
    assert too_few_volatility.disposition is AdvancedRiskDisposition.PAUSE


def test_favorable_realized_slippage_may_be_negative() -> None:
    result = evaluate(
        ModerateAdvancedRiskRuleId.REALIZED_EXECUTION_SLIPPAGE_BPS,
        Decimal("-4.25"),
        AdvancedRiskEvaluationMode.RUNTIME,
    )

    assert result.observed_value == Decimal("-4.25")
    assert result.disposition is AdvancedRiskDisposition.NONE
    with pytest.raises(AdvancedRiskPolicyError, match="non-negative"):
        observation(
            ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
            value=Decimal("-0.01"),
        )


def test_conservative_projection_ceil_prevents_hidden_subscale_breach() -> None:
    threshold = Decimal("0.35")

    assert conservative_positive_risk_decimal(
        Decimal("0.35000000000000000001"),
        "concentration",
    ) == Decimal("0.3500000001")
    assert conservative_positive_risk_decimal(threshold, "concentration") == threshold
    assert conservative_positive_risk_decimal(
        Decimal("1e-999999"),
        "concentration",
    ) == Decimal("0.0000000001")
    with pytest.raises(AdvancedRiskPolicyError, match="non-negative"):
        conservative_positive_risk_decimal(Decimal("-0.1"), "concentration")


def test_sip_quote_evidence_must_be_strictly_younger_than_five_seconds() -> None:
    retained = observation(
        ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
        value=Decimal("20"),
    )

    fresh = evaluate_moderate_advanced_risk(
        retained,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        assessed_at=NOW + timedelta(seconds=4, microseconds=999_999),
    )
    stale = evaluate_moderate_advanced_risk(
        retained,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        assessed_at=NOW + timedelta(seconds=5),
    )

    assert fresh.disposition is AdvancedRiskDisposition.NONE
    assert stale.effective_completeness is AdvancedRiskObservationCompleteness.UNAVAILABLE
    assert stale.disposition is AdvancedRiskDisposition.REJECT
    assert stale.reason_code == "evidence_stale"


def test_policy_digest_and_evaluation_ignore_ambient_decimal_context() -> None:
    before = evaluate(
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        Decimal("0.3500000001"),
        AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
    )
    with localcontext() as context:
        context.prec = 2
        context.rounding = "ROUND_FLOOR"
        during_digest = MODERATE_ADVANCED_RISK_POLICY.semantic_sha256
        during = evaluate(
            ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
            Decimal("0.3500000001"),
            AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        )

    assert during_digest == MODERATE_ADVANCED_RISK_POLICY_SHA256
    assert during.semantic_sha256 == before.semantic_sha256
    assert during.disposition is AdvancedRiskDisposition.REJECT


def test_aggregate_uses_mode_safe_severity_and_pretrade_never_trips() -> None:
    pretrade = aggregate_moderate_advanced_risk(
        (
            evaluate(
                ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
                Decimal("1.01"),
                AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            ),
            evaluate(
                ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
                Decimal("0"),
                AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            ),
        ),
        assessed_at=NOW + timedelta(seconds=3),
    )
    runtime = aggregate_moderate_advanced_risk(
        (
            evaluate(
                ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO,
                Decimal("0.021"),
                AdvancedRiskEvaluationMode.RUNTIME,
            ),
            evaluate(
                ModerateAdvancedRiskRuleId.SESSION_DRAWDOWN_RATIO,
                Decimal("0.041"),
                AdvancedRiskEvaluationMode.RUNTIME,
            ),
        ),
        assessed_at=NOW + timedelta(seconds=3),
    )

    assert pretrade.disposition is AdvancedRiskDisposition.REJECT
    assert pretrade.requires_control_trip is False
    assert runtime.disposition is AdvancedRiskDisposition.HALT
    assert runtime.requires_control_trip is True


def _full_observations(
    mode: AdvancedRiskEvaluationMode,
    required_instrument_ids: tuple[str, ...],
) -> tuple[AdvancedRiskPolicyObservation, ...]:
    items: list[AdvancedRiskPolicyObservation] = []
    for rule in MODERATE_ADVANCED_RISK_RULES:
        threshold = (
            rule.pretrade_reject_threshold
            if mode is AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE
            else rule.runtime_pause_threshold
        )
        if threshold is None:
            continue
        subjects = (
            required_instrument_ids
            if rule.rule_id
            in {
                ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
                ModerateAdvancedRiskRuleId.VOLATILITY_MAX_ABS_1M_RETURN_RATIO,
                ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS,
                ModerateAdvancedRiskRuleId.PROJECTED_EXECUTION_COST_BPS,
            }
            else (ACCOUNT_ID,)
        )
        for subject in subjects:
            items.append(observation(rule.rule_id, value=threshold, subject_id=subject))
    return tuple(sorted(items, key=lambda item: (item.rule_id.value, item.subject_id)))


def test_full_policy_assessment_requires_exact_applicable_coverage() -> None:
    required = ("US-ETF-QQQ", "US-ETF-SPY")
    complete = _full_observations(
        AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        required,
    )

    result = assess_moderate_advanced_risk(
        complete,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        required_instrument_ids=required,
        assessed_at=NOW + timedelta(seconds=3),
    )

    assert result.disposition is AdvancedRiskDisposition.NONE
    with pytest.raises(AdvancedRiskPolicyConflict, match="exact applicable rule coverage"):
        assess_moderate_advanced_risk(
            complete[:-1],
            mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            required_instrument_ids=required,
            assessed_at=NOW + timedelta(seconds=3),
        )
    with pytest.raises(AdvancedRiskPolicyConflict, match="exact applicable rule coverage"):
        assess_moderate_advanced_risk(
            complete,
            mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            required_instrument_ids=("US-ETF-SPY",),
            assessed_at=NOW + timedelta(seconds=3),
        )


def test_observation_validation_rejects_bad_scope_digest_and_chronology() -> None:
    retained = observation(ModerateAdvancedRiskRuleId.SIP_NBBO_FULL_SPREAD_BPS)

    with pytest.raises(AdvancedRiskPolicyError, match="outside policy scope"):
        replace(retained, subject_id="SPY")
    with pytest.raises(AdvancedRiskPolicyError, match="SHA-256"):
        replace(retained, evidence_sha256="not-a-digest")
    with pytest.raises(AdvancedRiskPolicyError, match="chronology"):
        replace(retained, window_ended_at=retained.window_started_at)
    with pytest.raises(AdvancedRiskPolicyError, match="UTC"):
        replace(
            retained,
            observed_at=retained.observed_at.astimezone(timezone(timedelta(hours=-4))),
        )


def test_aggregate_rejects_duplicate_or_conflicting_facts() -> None:
    result = evaluate(
        ModerateAdvancedRiskRuleId.DATA_HEALTH_UNHEALTHY,
        Decimal("0"),
        AdvancedRiskEvaluationMode.RUNTIME,
    )
    with pytest.raises(AdvancedRiskPolicyConflict, match="repeats"):
        aggregate_moderate_advanced_risk(
            (result, result),
            assessed_at=NOW + timedelta(seconds=3),
        )
    with pytest.raises(AdvancedRiskPolicyConflict, match="scope conflicts"):
        aggregate_moderate_advanced_risk(
            (
                result,
                replace(
                    result,
                    account_id="other-account",
                    subject_id="other-account",
                ),
            ),
            assessed_at=NOW + timedelta(seconds=3),
        )
