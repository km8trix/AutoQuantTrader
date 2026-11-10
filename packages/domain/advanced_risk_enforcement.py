"""Pure Phase 5B advanced-risk to operational-control trip binding.

An aggregate runtime assessment is evidence, not a command.  This module
performs the narrow deterministic translation from an authenticated assessment
that requires intervention to the existing Phase 5A circuit-breaker command.
Persistence remains responsible for authenticating the assignment, evidence,
lease fence, and exact control head and for committing both facts atomically.
"""

from __future__ import annotations

import hashlib

from packages.domain.advanced_risk_policy import (
    ADVANCED_RISK_POLICY_CONTRACT_VERSION,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyAssessment,
    AdvancedRiskRuleAssessment,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)

ADVANCED_RISK_BREAKER_ACTOR_ID = "phase5b-moderate-risk-breaker"
ADVANCED_RISK_BREAKER_AUTHORITY_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        (
            ADVANCED_RISK_POLICY_CONTRACT_VERSION,
            "advanced_risk_breaker_authority",
            ADVANCED_RISK_BREAKER_ACTOR_ID,
            "runtime_assessment_only",
            "pause_or_halt_only",
            "never_rearm",
        )
    )
).hexdigest()


class AdvancedRiskEnforcementError(ValueError):
    """An assessment cannot safely produce an operational-control trip."""


def _trip_rule(
    assessment: AdvancedRiskPolicyAssessment,
) -> AdvancedRiskRuleAssessment:
    expected = assessment.disposition
    for rule_assessment in assessment.rule_assessments:
        if rule_assessment.disposition is expected:
            return rule_assessment
    raise AdvancedRiskEnforcementError(
        "advanced-risk aggregate has no rule matching its trip disposition"
    )


def advanced_risk_trip_command(
    assessment: AdvancedRiskPolicyAssessment,
    *,
    assessment_evidence_sha256: str | None = None,
) -> OperationalControlCommand:
    """Bind one PAUSE/HALT runtime assessment to an idempotent breaker command.

    The pure default binds the assessment's domain digest.  Atomic persistence
    supplies the authenticated assessment-envelope digest so the durable trip
    also commits to its retained sources, assignment, fence, and pre-control
    head.
    """

    if type(assessment) is not AdvancedRiskPolicyAssessment:
        raise AdvancedRiskEnforcementError("advanced-risk trip requires an exact policy assessment")
    assessment.__post_init__()
    if assessment.mode is not AdvancedRiskEvaluationMode.RUNTIME:
        raise AdvancedRiskEnforcementError(
            "pretrade advanced-risk rejection cannot trip operational control"
        )
    if assessment.disposition not in {
        AdvancedRiskDisposition.PAUSE,
        AdvancedRiskDisposition.HALT,
    }:
        raise AdvancedRiskEnforcementError("advanced-risk trip requires a PAUSE or HALT assessment")
    if assessment_evidence_sha256 is not None and (
        type(assessment_evidence_sha256) is not str
        or len(assessment_evidence_sha256) != 64
        or any(character not in "0123456789abcdef" for character in assessment_evidence_sha256)
    ):
        raise AdvancedRiskEnforcementError(
            "advanced-risk trip assessment evidence must be a lowercase SHA-256 digest"
        )
    selected = _trip_rule(assessment)
    target = (
        OperationalControlState.HALTED
        if assessment.disposition is AdvancedRiskDisposition.HALT
        else OperationalControlState.PAUSED
    )
    return OperationalControlCommand(
        scope_id=assessment.account_id,
        idempotency_key=f"advanced-risk-trip:{assessment.assessment_id}",
        kind=OperationalControlCommandKind.TRIP,
        target_state=target,
        actor=OperationalControlActor(
            actor_id=ADVANCED_RISK_BREAKER_ACTOR_ID,
            kind=OperationalControlActorKind.CIRCUIT_BREAKER,
            authority_sha256=ADVANCED_RISK_BREAKER_AUTHORITY_SHA256,
            authenticated_at=None,
        ),
        reason_code=f"advanced_risk_{assessment.disposition.value}",
        reason_evidence_sha256=(
            assessment.semantic_sha256
            if assessment_evidence_sha256 is None
            else assessment_evidence_sha256
        ),
        requested_at=assessment.assessed_at,
        trip_rule_id=selected.rule_id.value,
        trip_policy_sha256=assessment.policy_sha256,
        trip_observation_sha256=selected.observation_sha256,
    )
