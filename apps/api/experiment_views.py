"""Read-only HTTP projections for bounded Phase 3 experiment governance."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Protocol

from fastapi import APIRouter, HTTPException, Path, Query, status
from sqlalchemy.exc import SQLAlchemyError

from apps.api.contracts import (
    ApiErrorResponse,
    ExperimentAttemptEventView,
    ExperimentAttemptView,
    ExperimentEvaluationReceiptView,
    ExperimentHoldoutState,
    ExperimentHoldoutView,
    ExperimentListResponse,
    ExperimentPromotionCriteriaView,
    ExperimentPromotionCriterionView,
    ExperimentResponse,
    ExperimentSegmentView,
    ExperimentSummaryView,
    ExperimentView,
)
from packages.domain.experiment_governance import (
    ExperimentGovernanceSnapshot,
    GovernedSegmentEvaluationReceipt,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.persistence.experiment_governance import (
    ExperimentGovernanceError,
    ExperimentGovernanceNotFound,
)

logger = logging.getLogger(__name__)


class ExperimentGovernanceQuery(Protocol):
    """Minimal authenticated query boundary needed by the HTTP surface."""

    def families(self, *, limit: int = 100) -> tuple[ExperimentGovernanceSnapshot, ...]: ...

    def get(self, family_id: str) -> ExperimentGovernanceSnapshot: ...


def experiment_summary_view(
    snapshot: ExperimentGovernanceSnapshot,
) -> ExperimentSummaryView:
    """Project only bounded family metadata and opaque holdout identity."""

    if type(snapshot) is not ExperimentGovernanceSnapshot:
        raise TypeError("experiment query returned an unexpected snapshot type")
    family = snapshot.family
    criteria = family.promotion_criteria
    pre_holdout_attempt_count = sum(
        attempt.segment_kind is not EvaluationSegmentKind.TEST for attempt in snapshot.attempts
    )
    holdout_state = (
        ExperimentHoldoutState.SEALED
        if snapshot.holdout_reveal is None
        else ExperimentHoldoutState.REVEALED
    )
    return ExperimentSummaryView(
        family_id=family.family_id,
        family_name=family.family_name,
        hypothesis=family.hypothesis,
        owner_id=family.owner_id,
        created_at=family.created_at,
        strategy_id=family.strategy_version.strategy_id,
        strategy_version=family.strategy_version.strategy_version,
        strategy_version_sha256=family.strategy_version.semantic_sha256,
        evaluation_plan_version=family.evaluation_plan_version,
        evaluation_plan_sha256=family.evaluation_plan_sha256,
        promotion_criteria_sha256=criteria.semantic_sha256,
        test_commitment_sha256=family.test_commitment.semantic_sha256,
        maximum_pre_holdout_trials=criteria.maximum_pre_holdout_trials,
        pre_holdout_attempt_count=pre_holdout_attempt_count,
        remaining_pre_holdout_attempts=(
            0
            if holdout_state is ExperimentHoldoutState.REVEALED
            else max(
                0,
                criteria.maximum_pre_holdout_trials - pre_holdout_attempt_count,
            )
        ),
        attempt_count=len(snapshot.attempts),
        holdout_state=holdout_state,
        snapshot_sha256=snapshot.semantic_sha256,
        registry_head_sha256=snapshot.registry_head_sha256,
    )


def _segment_views(
    snapshot: ExperimentGovernanceSnapshot,
) -> list[ExperimentSegmentView]:
    return [
        ExperimentSegmentView(
            kind=segment.kind,
            segment_sha256=(
                None
                if segment.kind is EvaluationSegmentKind.TEST and snapshot.holdout_reveal is None
                else segment.semantic_sha256
            ),
            coverage_start=segment.coverage_start,
            coverage_end=segment.coverage_end,
            dataset_replay_sha256=(
                None
                if segment.kind is EvaluationSegmentKind.TEST and snapshot.holdout_reveal is None
                else segment.dataset_replay_sha256
            ),
            purge_before=segment.purge_before,
            embargo_after=segment.embargo_after,
        )
        for segment in snapshot.family.segments
    ]


def _promotion_criteria_view(
    snapshot: ExperimentGovernanceSnapshot,
) -> ExperimentPromotionCriteriaView:
    criteria = snapshot.family.promotion_criteria
    return ExperimentPromotionCriteriaView(
        criteria_sha256=criteria.semantic_sha256,
        criteria_version=criteria.criteria_version,
        criteria=[
            ExperimentPromotionCriterionView(
                metric_name=criterion.metric_name,
                comparison=criterion.comparison,
                threshold=criterion.threshold,
                minimum_observations=criterion.minimum_observations,
            )
            for criterion in criteria.criteria
        ],
        selection_rule=criteria.selection_rule,
        multiple_testing_method=criteria.multiple_testing_method,
        maximum_pre_holdout_trials=criteria.maximum_pre_holdout_trials,
        frozen_at=criteria.frozen_at,
        frozen_by=criteria.frozen_by,
    )


def _evaluation_receipt_view(
    evidence: object,
) -> ExperimentEvaluationReceiptView | None:
    if type(evidence) is not GovernedSegmentEvaluationReceipt:
        return None
    return ExperimentEvaluationReceiptView(
        evidence_kind=evidence.evidence_kind,
        family_id=evidence.family_id,
        attempt_id=evidence.attempt_id,
        receipt_sha256=evidence.semantic_sha256,
        strategy_version_sha256=evidence.strategy_version_sha256,
        configuration_sha256=evidence.configuration_sha256,
        configuration_validation_sha256=(evidence.configuration_validation_sha256),
        segment_kind=evidence.segment_kind,
        segment_sha256=evidence.segment_sha256,
        source_evidence_sha256=evidence.source_evidence_sha256,
        holdout_reveal_sha256=evidence.holdout_reveal_sha256,
        feature_certification_sha256=evidence.feature_certification_sha256,
        target_policy_sha256=evidence.target_policy_sha256,
        target_runtime_pin_sha256=evidence.target_runtime_pin_sha256,
        target_certification_sha256=evidence.target_certification_sha256,
        batch_result_sha256=evidence.batch_result_sha256,
        incremental_result_sha256=evidence.incremental_result_sha256,
        target_parity_receipt_sha256=evidence.target_parity_receipt_sha256,
        target_transcript_sha256=evidence.target_transcript_sha256,
        step_count=evidence.step_count,
        target_count=evidence.target_count,
        running_event_sha256=evidence.running_event_sha256,
        started_at=evidence.started_at,
        completed_at=evidence.completed_at,
        evaluated_by=evidence.evaluated_by,
    )


def _attempt_views(
    snapshot: ExperimentGovernanceSnapshot,
) -> list[ExperimentAttemptView]:
    events_by_attempt = {
        attempt.attempt_id: [
            event for event in snapshot.lifecycle_events if event.attempt_id == attempt.attempt_id
        ]
        for attempt in snapshot.attempts
    }
    attempts: list[ExperimentAttemptView] = []
    for attempt in snapshot.attempts:
        history = events_by_attempt[attempt.attempt_id]
        if not history:
            raise ValueError("experiment attempt has no lifecycle history")
        attempts.append(
            ExperimentAttemptView(
                attempt_id=attempt.attempt_id,
                attempt_number=attempt.attempt_number,
                configuration_sha256=attempt.configuration.semantic_sha256,
                configuration_name=attempt.configuration.configuration_name,
                configuration_validation_sha256=(attempt.configuration_validation.semantic_sha256),
                segment_kind=attempt.segment_kind,
                segment_sha256=attempt.segment_sha256,
                requested_at=attempt.requested_at,
                requested_by=attempt.requested_by,
                holdout_reveal_sha256=attempt.holdout_reveal_sha256,
                status=history[-1].status,
                history=[
                    ExperimentAttemptEventView(
                        event_sha256=event.semantic_sha256,
                        global_sequence_number=event.global_sequence_number,
                        attempt_sequence_number=event.attempt_sequence_number,
                        status=event.status,
                        occurred_at=event.occurred_at,
                        actor_id=event.actor_id,
                        terminal_evidence_sha256=(
                            None
                            if event.terminal_evidence is None
                            else event.terminal_evidence.semantic_sha256
                        ),
                        terminal_reason_code=(
                            None
                            if event.terminal_evidence is None
                            else event.terminal_evidence.reason_code
                        ),
                        evaluation=_evaluation_receipt_view(event.terminal_evidence),
                    )
                    for event in history
                ],
            )
        )
    return attempts


def _holdout_view(snapshot: ExperimentGovernanceSnapshot) -> ExperimentHoldoutView:
    commitment_sha256 = snapshot.family.test_commitment.semantic_sha256
    reveal = snapshot.holdout_reveal
    if reveal is None:
        return ExperimentHoldoutView(
            state=ExperimentHoldoutState.SEALED,
            commitment_sha256=commitment_sha256,
            authorization_sha256=None,
            reveal_sha256=None,
            selected_configuration_sha256=None,
            pre_reveal_snapshot_sha256=None,
            pre_reveal_registry_head_sha256=None,
            pre_reveal_attempts_sha256=None,
            pre_reveal_attempt_count=None,
            revealed_at=None,
            revealed_by=None,
            access_reason=None,
        )
    authorization = reveal.authorization
    return ExperimentHoldoutView(
        state=ExperimentHoldoutState.REVEALED,
        commitment_sha256=commitment_sha256,
        authorization_sha256=authorization.semantic_sha256,
        reveal_sha256=reveal.semantic_sha256,
        selected_configuration_sha256=authorization.selected_configuration_sha256,
        pre_reveal_snapshot_sha256=authorization.pre_reveal_snapshot_sha256,
        pre_reveal_registry_head_sha256=authorization.pre_reveal_head_sha256,
        pre_reveal_attempts_sha256=authorization.pre_reveal_attempts_sha256,
        pre_reveal_attempt_count=authorization.pre_reveal_attempt_count,
        revealed_at=reveal.revealed_at,
        revealed_by=reveal.revealed_by,
        access_reason=reveal.access_reason,
    )


def experiment_view(snapshot: ExperimentGovernanceSnapshot) -> ExperimentView:
    """Project authenticated governance without disclosing held-out evidence."""

    return ExperimentView(
        summary=experiment_summary_view(snapshot),
        segments=_segment_views(snapshot),
        promotion_criteria=_promotion_criteria_view(snapshot),
        attempts=_attempt_views(snapshot),
        holdout=_holdout_view(snapshot),
    )


def _unavailable(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)


def _require_repository(
    repository: ExperimentGovernanceQuery | None,
    persistence_ready: Callable[[], bool],
) -> ExperimentGovernanceQuery:
    if repository is None or not persistence_ready():
        raise _unavailable("durable experiment-governance persistence is unavailable")
    return repository


def create_experiment_router(
    *,
    repository: ExperimentGovernanceQuery | None,
    persistence_ready: Callable[[], bool],
) -> APIRouter:
    """Build GET-only experiment inspection routes."""

    router = APIRouter(prefix="/research")

    @router.get(
        "/experiments",
        response_model=ExperimentListResponse,
        responses={
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "Durable experiment governance is unavailable.",
            }
        },
        tags=["research"],
    )
    def experiments(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> ExperimentListResponse:
        resolved = _require_repository(repository, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            snapshots = resolved.families(limit=limit)
            if type(snapshots) is not tuple:
                raise TypeError("experiment family query must return an immutable tuple")
            return ExperimentListResponse(
                as_of=queried_at,
                experiments=[experiment_summary_view(snapshot) for snapshot in snapshots],
            )
        except (
            SQLAlchemyError,
            ExperimentGovernanceError,
            ValueError,
            TypeError,
            AttributeError,
        ) as error:
            logger.exception("experiment family list read failed")
            raise _unavailable("experiment families are unavailable or malformed") from error

    @router.get(
        "/experiments/{family_id}",
        response_model=ExperimentResponse,
        responses={
            status.HTTP_404_NOT_FOUND: {
                "model": ApiErrorResponse,
                "description": "Experiment family not found.",
            },
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ApiErrorResponse,
                "description": "Durable experiment governance is unavailable.",
            },
        },
        tags=["research"],
    )
    def experiment(
        family_id: Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")],
    ) -> ExperimentResponse:
        resolved = _require_repository(repository, persistence_ready)
        queried_at = datetime.now(UTC)
        try:
            return ExperimentResponse(
                as_of=queried_at,
                experiment=experiment_view(resolved.get(family_id)),
            )
        except ExperimentGovernanceNotFound as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="experiment family was not found",
            ) from error
        except (
            SQLAlchemyError,
            ExperimentGovernanceError,
            ValueError,
            TypeError,
            AttributeError,
        ) as error:
            logger.exception("experiment family read failed")
            raise _unavailable("experiment family is unavailable or malformed") from error

    return router


__all__ = [
    "ExperimentGovernanceQuery",
    "create_experiment_router",
    "experiment_summary_view",
    "experiment_view",
]
