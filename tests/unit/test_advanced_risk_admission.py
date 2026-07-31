from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.domain.advanced_risk_admission import (
    AdvancedBatchRiskOutcome,
    AdvancedRiskAdmissionConflict,
    AdvancedRiskAssessmentReference,
    AdvancedRiskBatchAdmission,
    AdvancedRiskEvidenceWatermark,
)
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_POLICY_SHA256,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
)
from packages.domain.batch_risk import (
    BatchRiskDecisionStatus,
    evaluate_batch_risk_decision,
    initial_active_capacity_universe,
)
from packages.domain.operational_control import OperationalControlState
from tests.unit.test_batch_risk import EVALUATED_AT, limits, mixed_case


def _watermark(*, capacity_sha256: str) -> AdvancedRiskEvidenceWatermark:
    _portfolio, target, batch, snapshot = mixed_case()
    return AdvancedRiskEvidenceWatermark(
        account_id=snapshot.account_id,
        intent_batch_id=batch.intent_batch_id,
        intent_batch_sha256=batch.semantic_sha256,
        target_id=target.target_id,
        target_sha256=target.semantic_sha256,
        snapshot_version=snapshot.version,
        snapshot_sha256=snapshot.semantic_sha256,
        active_capacity_sha256=capacity_sha256,
        phase2_policy_sha256=limits().semantic_sha256,
        fencing_generation=1,
        fence_sha256="1" * 64,
        runtime_instrument_ids=("US-ETF-IWM", "US-ETF-SPY"),
        pretrade_instrument_ids=("US-ETF-IWM", "US-ETF-SPY"),
        evaluated_at=EVALUATED_AT,
    )


def _reference(
    watermark: AdvancedRiskEvidenceWatermark,
    *,
    mode: AdvancedRiskEvaluationMode,
    disposition: AdvancedRiskDisposition,
    suffix: str,
) -> AdvancedRiskAssessmentReference:
    return AdvancedRiskAssessmentReference(
        account_id=watermark.account_id,
        assessment_id=suffix * 36,
        assessment_sha256=suffix * 64,
        policy_sha256=MODERATE_ADVANCED_RISK_POLICY_SHA256,
        mode=mode,
        disposition=disposition,
        assignment_id="a" * 36,
        assignment_sequence_number=1,
        assignment_sha256="b" * 64,
        observation_watermark_sequence=10,
        watermark_evidence_id="c" * 36,
        watermark_evidence_sha256="d" * 64,
        operational_transition_id="e" * 36,
        operational_transition_sha256="f" * 64,
        evidence_context_sha256=watermark.semantic_sha256,
        assessed_at=EVALUATED_AT,
        valid_through=EVALUATED_AT + timedelta(seconds=20),
    )


def test_exposure_watermark_binds_active_capacity_and_scopes() -> None:
    first = _watermark(capacity_sha256="2" * 64)
    second = replace(first, active_capacity_sha256="3" * 64)

    assert first.watermark_id != second.watermark_id
    assert first.semantic_sha256 != second.semantic_sha256


def test_admitted_sidecar_requires_approved_none_and_running() -> None:
    _portfolio, target, batch, snapshot = mixed_case()
    capacity = initial_active_capacity_universe(snapshot.account_id)
    decision = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=snapshot,
        limits=limits(),
        active_capacity=capacity,
        evaluated_at=EVALUATED_AT,
    )
    assert decision.status is BatchRiskDecisionStatus.APPROVED
    watermark = _watermark(capacity_sha256=capacity.semantic_sha256)
    runtime = _reference(
        watermark,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        disposition=AdvancedRiskDisposition.NONE,
        suffix="1",
    )
    pretrade = _reference(
        watermark,
        mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
        disposition=AdvancedRiskDisposition.NONE,
        suffix="2",
    )
    admission = AdvancedRiskBatchAdmission(
        account_id=decision.account_id,
        phase2_decision_id=decision.decision_id,
        phase2_decision_sha256=decision.semantic_sha256,
        phase2_decision_status=decision.status,
        fencing_generation=1,
        lease_sha256="3" * 64,
        fence_sha256="1" * 64,
        assessment=pretrade,
        operational_transition_id=pretrade.operational_transition_id,
        operational_transition_sha256=pretrade.operational_transition_sha256,
        operational_state=OperationalControlState.RUNNING,
        admitted=True,
        bound_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(seconds=10),
    )
    outcome = AdvancedBatchRiskOutcome(
        watermark=watermark,
        assignment_id=runtime.assignment_id,
        assignment_sequence_number=runtime.assignment_sequence_number,
        assignment_sha256=runtime.assignment_sha256,
        runtime_assessment=runtime,
        pretrade_assessment=pretrade,
        pre_control_transition_id=runtime.operational_transition_id,
        pre_control_transition_sha256=runtime.operational_transition_sha256,
        final_control_transition_id=runtime.operational_transition_id,
        final_control_transition_sha256=runtime.operational_transition_sha256,
        final_control_state=OperationalControlState.RUNNING,
        phase2_decision=decision,
        admission=admission,
    )

    assert outcome.admission is not None and outcome.admission.admitted
    with pytest.raises(AdvancedRiskAdmissionConflict, match="admission flag"):
        replace(
            admission,
            operational_state=OperationalControlState.PAUSED,
        )


def test_no_action_sidecar_requires_exact_null_assessment_shape() -> None:
    portfolio, _target, _batch, snapshot = mixed_case()
    from tests.unit.test_batch_risk import make_batch

    target, batch = make_batch(
        portfolio,
        desired={position.instrument_id: position.quantity for position in portfolio.positions},
        target_id="no-action-target",
    )
    capacity = initial_active_capacity_universe(snapshot.account_id)
    decision = evaluate_batch_risk_decision(
        batch=batch,
        target=target,
        snapshot=snapshot,
        limits=limits(),
        active_capacity=capacity,
        evaluated_at=EVALUATED_AT,
    )
    assert decision.status is BatchRiskDecisionStatus.NO_ACTION
    admission = AdvancedRiskBatchAdmission(
        account_id=decision.account_id,
        phase2_decision_id=decision.decision_id,
        phase2_decision_sha256=decision.semantic_sha256,
        phase2_decision_status=decision.status,
        fencing_generation=1,
        lease_sha256="3" * 64,
        fence_sha256="1" * 64,
        assessment=None,
        operational_transition_id="e" * 36,
        operational_transition_sha256="f" * 64,
        operational_state=OperationalControlState.RUNNING,
        admitted=False,
        bound_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(seconds=10),
    )

    assert admission.assessment is None
    with pytest.raises(AdvancedRiskAdmissionConflict, match="NO_ACTION"):
        replace(
            admission,
            assessment=_reference(
                _watermark(capacity_sha256=capacity.semantic_sha256),
                mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
                disposition=AdvancedRiskDisposition.NONE,
                suffix="4",
            ),
        )
