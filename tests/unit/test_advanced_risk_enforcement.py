from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from packages.domain.advanced_risk import AdvancedRiskObservationCompleteness
from packages.domain.advanced_risk_enforcement import (
    ADVANCED_RISK_BREAKER_ACTOR_ID,
    ADVANCED_RISK_BREAKER_AUTHORITY_SHA256,
    AdvancedRiskEnforcementError,
    advanced_risk_trip_command,
)
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_POLICY,
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    MODERATE_ADVANCED_RISK_RULES,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyAssessment,
    AdvancedRiskRuleAssessment,
    AdvancedRiskThresholdComparator,
    ModerateAdvancedRiskRuleId,
)
from packages.domain.operational_control import (
    OperationalControlActorKind,
    OperationalControlCommandKind,
    OperationalControlState,
)

ASSESSED_AT = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)
ACCOUNT_ID = "paper-account-1"


def _rule_assessment(
    rule_id: ModerateAdvancedRiskRuleId,
    disposition: AdvancedRiskDisposition,
) -> AdvancedRiskRuleAssessment:
    rule = next(item for item in MODERATE_ADVANCED_RISK_RULES if item.rule_id is rule_id)
    threshold = (
        rule.runtime_halt_threshold
        if disposition is AdvancedRiskDisposition.HALT
        else rule.runtime_pause_threshold
    )
    return AdvancedRiskRuleAssessment(
        account_id=ACCOUNT_ID,
        environment="paper",
        policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        rule_id=rule_id,
        subject_id=ACCOUNT_ID,
        observation_sha256="a" * 64,
        evidence_sha256="b" * 64,
        producer_authority_sha256=rule.producer_authority_sha256,
        source_authority_sha256=rule.source_authority_sha256,
        source_set_sha256="c" * 64,
        input_completeness=AdvancedRiskObservationCompleteness.COMPLETE,
        effective_completeness=AdvancedRiskObservationCompleteness.COMPLETE,
        observed_value=Decimal("4"),
        sample_count=1,
        qualifying_count=None,
        threshold=threshold,
        comparator=AdvancedRiskThresholdComparator.STRICTLY_GREATER,
        disposition=disposition,
        reason_code=f"runtime_{disposition.value}_limit_breached",
        assessed_at=ASSESSED_AT,
    )


def _assessment(
    disposition: AdvancedRiskDisposition,
) -> AdvancedRiskPolicyAssessment:
    rule_id = ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO
    return AdvancedRiskPolicyAssessment(
        account_id=ACCOUNT_ID,
        environment="paper",
        policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        rule_assessments=(_rule_assessment(rule_id, disposition),),
        disposition=disposition,
        assessed_at=ASSESSED_AT,
    )


@pytest.mark.parametrize(
    ("disposition", "state"),
    (
        (AdvancedRiskDisposition.PAUSE, OperationalControlState.PAUSED),
        (AdvancedRiskDisposition.HALT, OperationalControlState.HALTED),
    ),
)
def test_runtime_assessment_maps_to_exact_idempotent_trip(
    disposition: AdvancedRiskDisposition,
    state: OperationalControlState,
) -> None:
    assessment = _assessment(disposition)

    first = advanced_risk_trip_command(assessment)
    second = advanced_risk_trip_command(assessment)

    assert first == second
    assert first.kind is OperationalControlCommandKind.TRIP
    assert first.target_state is state
    assert first.actor.actor_id == ADVANCED_RISK_BREAKER_ACTOR_ID
    assert first.actor.kind is OperationalControlActorKind.CIRCUIT_BREAKER
    assert first.actor.authority_sha256 == ADVANCED_RISK_BREAKER_AUTHORITY_SHA256
    assert first.reason_evidence_sha256 == assessment.semantic_sha256
    assert first.trip_rule_id == ModerateAdvancedRiskRuleId.SESSION_LOSS_RATIO.value
    assert first.trip_policy_sha256 == MODERATE_ADVANCED_RISK_POLICY_SHA256
    assert first.trip_observation_sha256 == "a" * 64
    assert first.requested_at == ASSESSED_AT


def test_non_breaching_runtime_assessment_cannot_create_trip() -> None:
    with pytest.raises(AdvancedRiskEnforcementError, match="PAUSE or HALT"):
        advanced_risk_trip_command(_assessment(AdvancedRiskDisposition.NONE))


def test_pretrade_rejection_cannot_create_trip() -> None:
    runtime = _assessment(AdvancedRiskDisposition.PAUSE)
    pretrade_rule = runtime.rule_assessments[0]
    pretrade_rule = AdvancedRiskRuleAssessment(
        account_id=pretrade_rule.account_id,
        environment=pretrade_rule.environment,
        policy_id=pretrade_rule.policy_id,
        policy_sha256=pretrade_rule.policy_sha256,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        rule_id=pretrade_rule.rule_id,
        subject_id=pretrade_rule.subject_id,
        observation_sha256=pretrade_rule.observation_sha256,
        evidence_sha256=pretrade_rule.evidence_sha256,
        producer_authority_sha256=pretrade_rule.producer_authority_sha256,
        source_authority_sha256=pretrade_rule.source_authority_sha256,
        source_set_sha256=pretrade_rule.source_set_sha256,
        input_completeness=pretrade_rule.input_completeness,
        effective_completeness=pretrade_rule.effective_completeness,
        observed_value=pretrade_rule.observed_value,
        sample_count=pretrade_rule.sample_count,
        qualifying_count=pretrade_rule.qualifying_count,
        threshold=Decimal("0.02"),
        comparator=pretrade_rule.comparator,
        disposition=AdvancedRiskDisposition.REJECT,
        reason_code="pretrade_limit_breached",
        assessed_at=pretrade_rule.assessed_at,
    )
    assessment = AdvancedRiskPolicyAssessment(
        account_id=ACCOUNT_ID,
        environment="paper",
        policy_id=MODERATE_ADVANCED_RISK_POLICY.policy_id,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        rule_assessments=(pretrade_rule,),
        disposition=AdvancedRiskDisposition.REJECT,
        assessed_at=ASSESSED_AT,
    )

    with pytest.raises(AdvancedRiskEnforcementError, match="cannot trip"):
        advanced_risk_trip_command(assessment)
