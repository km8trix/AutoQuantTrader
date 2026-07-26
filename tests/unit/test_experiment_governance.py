from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, dataclass, fields, replace
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, cast

import pytest

from packages.domain.canonical import canonical_json_bytes
from packages.domain.experiment_governance import (
    EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
    EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION,
    GOVERNED_SEGMENT_EVALUATION,
    NON_EXECUTABLE_DOMAIN_FIXTURE,
    AuditedHoldoutReveal,
    ExperimentAttemptStatus,
    ExperimentGovernanceError,
    ExperimentGovernanceFamily,
    ExperimentGovernanceSnapshot,
    ExperimentSegmentEvidence,
    GovernedSegmentEvaluationReceipt,
    HoldoutRevealAuthorization,
    NonExecutableTerminalEvidence,
    StrategyConfigurationValidationReceipt,
)
from packages.domain.experiment_governance import (
    TestSegmentCommitment as HoldoutCommitment,
)
from packages.domain.experiment_registry import (
    EvaluationSegment,
    EvaluationSegmentKind,
    FrozenPromotionCriteria,
    PromotionComparison,
    PromotionCriterion,
    StrategyConfigurationRecord,
    StrategyVersionRecord,
)
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.feature_target import (
    CertifiedFeatureTargetReplay,
    RollingCloseMeanTargetPolicy,
)
from packages.domain.feature_target_replay import (
    certify_rolling_close_mean_target_parity,
)
from tests.unit.test_feature_target_replay import (
    BASE,
    _certify,
    _event,
    _replay,
    _watermark,
)

FAMILY_CREATED_AT = BASE + timedelta(days=2)
CRITERIA_FROZEN_AT = FAMILY_CREATED_AT + timedelta(hours=1)
CONFIGURATION_REGISTERED_AT = CRITERIA_FROZEN_AT + timedelta(minutes=1)
FIRST_ATTEMPT_AT = CRITERIA_FROZEN_AT + timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class GovernanceFixture:
    family: ExperimentGovernanceFamily
    configuration: StrategyConfigurationRecord
    validation: StrategyConfigurationValidationReceipt
    schema_payload: str
    train_certification: CertifiedFeatureReplay
    validation_certification: CertifiedFeatureReplay
    test_certification: CertifiedFeatureReplay


def _scoped_certification(
    start_index: int,
    *,
    prices: tuple[str, ...] = ("100", "102", "106", "99"),
    lag: timedelta = timedelta(seconds=30),
) -> CertifiedFeatureReplay:
    indexes = tuple(start_index + offset for offset in range(len(prices)))
    return _certify(
        _replay(
            prices,
            events=tuple(
                _event(index, price) for index, price in zip(indexes, prices, strict=True)
            ),
            watermarks=tuple(_watermark(index) for index in indexes),
        ),
        quantity="10",
        lag=lag,
    ).feature_certification


def _segment(
    kind: EvaluationSegmentKind,
    certification: CertifiedFeatureReplay,
) -> EvaluationSegment:
    replay = certification.batch_result.source_replay
    return EvaluationSegment(
        kind=kind,
        coverage_start=replay.batches[0].watermark.event_time_through,
        coverage_end=replay.batches[-1].watermark.event_time_through,
        dataset_replay_sha256=replay.semantic_sha256,
    )


def _schema_payload() -> str:
    return json.dumps(
        {
            "additionalProperties": False,
            "properties": {
                "long_quantity": {"type": "string"},
                "target_lifetime_seconds": {"type": "integer"},
            },
            "required": ["long_quantity", "target_lifetime_seconds"],
            "type": "object",
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _strategy_version(schema_payload: str) -> StrategyVersionRecord:
    return StrategyVersionRecord(
        strategy_id="rolling-close-mean-cross",
        strategy_version="1.0.0",
        code_sha256="1" * 64,
        parameter_schema_sha256=hashlib.sha256(schema_payload.encode("utf-8")).hexdigest(),
        state_schema_version="phase3d-stateless-v1",
        source_revision="2" * 40,
        registered_at=FAMILY_CREATED_AT - timedelta(hours=1),
        registered_by="phase3c-owner",
    )


def _configuration(
    strategy_version: StrategyVersionRecord,
    *,
    long_quantity: str = "10",
    target_lifetime_seconds: int = 300,
) -> StrategyConfigurationRecord:
    return StrategyConfigurationRecord(
        strategy_version_sha256=strategy_version.semantic_sha256,
        configuration_name=(f"long-{long_quantity}-for-{target_lifetime_seconds}-seconds"),
        parameters={
            "long_quantity": Decimal(long_quantity),
            "target_lifetime_seconds": target_lifetime_seconds,
        },
        registered_at=CONFIGURATION_REGISTERED_AT,
        registered_by="phase3c-owner",
    )


def _target_certification(
    feature_certification: CertifiedFeatureReplay,
    configuration: StrategyConfigurationRecord,
) -> CertifiedFeatureTargetReplay:
    parameters = configuration.parameters
    return certify_rolling_close_mean_target_parity(
        feature_certification,
        RollingCloseMeanTargetPolicy(
            long_quantity=parameters["long_quantity"],  # type: ignore[arg-type]
            target_lifetime=timedelta(
                seconds=parameters["target_lifetime_seconds"]  # type: ignore[arg-type]
            ),
        ),
    )


def _promotion_criteria(*, maximum_trials: int) -> FrozenPromotionCriteria:
    return FrozenPromotionCriteria(
        criteria_version="phase3c-fixture-v1",
        criteria=(
            PromotionCriterion(
                metric_name="total_return",
                comparison=PromotionComparison.GREATER_THAN_OR_EQUAL,
                threshold=Decimal("0"),
                minimum_observations=2,
            ),
        ),
        selection_rule="Select one configuration with completed validation evidence.",
        multiple_testing_method="declared-trial-budget-v1",
        maximum_pre_holdout_trials=maximum_trials,
        frozen_at=CRITERIA_FROZEN_AT,
        frozen_by="phase3c-owner",
    )


def _fixture(*, maximum_trials: int = 4) -> GovernanceFixture:
    train_certification = _scoped_certification(0)
    validation_certification = _scoped_certification(10)
    test_certification = _scoped_certification(20)
    train = _segment(EvaluationSegmentKind.TRAIN, train_certification)
    validation = _segment(EvaluationSegmentKind.VALIDATION, validation_certification)
    test = _segment(EvaluationSegmentKind.TEST, test_certification)
    schema_payload = _schema_payload()
    strategy_version = _strategy_version(schema_payload)
    configuration = _configuration(strategy_version)
    configuration_validation = StrategyConfigurationValidationReceipt.from_configuration(
        strategy_version,
        configuration,
        schema_payload,
    )
    family = ExperimentGovernanceFamily(
        family_name="phase3c-causal-reference",
        hypothesis="The bounded causal reference survives one final confirmation.",
        owner_id="phase3c-owner",
        created_at=FAMILY_CREATED_AT,
        strategy_version=strategy_version,
        evaluation_plan_version="phase3c-chronological-v1",
        segments=(train, validation, test),
        train_evidence=ExperimentSegmentEvidence.from_certification(
            train,
            train_certification,
        ),
        validation_evidence=ExperimentSegmentEvidence.from_certification(
            validation,
            validation_certification,
        ),
        test_commitment=HoldoutCommitment.from_certification(
            test,
            test_certification,
        ),
        promotion_criteria=_promotion_criteria(maximum_trials=maximum_trials),
    )
    return GovernanceFixture(
        family=family,
        configuration=configuration,
        validation=configuration_validation,
        schema_payload=schema_payload,
        train_certification=train_certification,
        validation_certification=validation_certification,
        test_certification=test_certification,
    )


def _request(
    snapshot: ExperimentGovernanceSnapshot,
    fixture: GovernanceFixture,
    *,
    kind: EvaluationSegmentKind,
    requested_at: datetime,
    configuration: StrategyConfigurationRecord | None = None,
    validation: StrategyConfigurationValidationReceipt | None = None,
) -> ExperimentGovernanceSnapshot:
    return snapshot.request_attempt(
        configuration=configuration or fixture.configuration,
        configuration_validation=validation or fixture.validation,
        segment_kind=kind,
        requested_at=requested_at,
        requested_by="phase3c-researcher",
    )


def _complete_latest(
    snapshot: ExperimentGovernanceSnapshot,
    fixture: GovernanceFixture,
    *,
    started_at: datetime,
    completed_at: datetime,
    certification: CertifiedFeatureTargetReplay | None = None,
    worker_id: str = "phase3c-worker",
) -> ExperimentGovernanceSnapshot:
    attempt = snapshot.attempts[-1]
    running = snapshot.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=started_at,
        actor_id=worker_id,
    )
    feature_certification = {
        EvaluationSegmentKind.TRAIN: fixture.train_certification,
        EvaluationSegmentKind.VALIDATION: fixture.validation_certification,
        EvaluationSegmentKind.TEST: fixture.test_certification,
    }[attempt.segment_kind]
    return running.complete_attempt(
        attempt.attempt_id,
        certification or _target_certification(feature_certification, attempt.configuration),
        completed_at=completed_at,
        actor_id=worker_id,
    )


def _restore_evaluation_receipt(
    receipt: GovernedSegmentEvaluationReceipt,
    **overrides: Any,
) -> GovernedSegmentEvaluationReceipt:
    payload: dict[str, Any] = {
        "family_id": receipt.family_id,
        "attempt_id": receipt.attempt_id,
        "strategy_version_sha256": receipt.strategy_version_sha256,
        "configuration_sha256": receipt.configuration_sha256,
        "configuration_validation_sha256": receipt.configuration_validation_sha256,
        "segment_kind": receipt.segment_kind,
        "segment_sha256": receipt.segment_sha256,
        "source_evidence_sha256": receipt.source_evidence_sha256,
        "holdout_reveal_sha256": receipt.holdout_reveal_sha256,
        "feature_certification_sha256": receipt.feature_certification_sha256,
        "target_policy_sha256": receipt.target_policy_sha256,
        "target_runtime_pin_sha256": receipt.target_runtime_pin_sha256,
        "target_certification_sha256": receipt.target_certification_sha256,
        "batch_result_sha256": receipt.batch_result_sha256,
        "incremental_result_sha256": receipt.incremental_result_sha256,
        "target_parity_receipt_sha256": receipt.target_parity_receipt_sha256,
        "target_transcript_sha256": receipt.target_transcript_sha256,
        "step_count": receipt.step_count,
        "target_count": receipt.target_count,
        "running_event_sha256": receipt.running_event_sha256,
        "started_at": receipt.started_at,
        "completed_at": receipt.completed_at,
        "evaluated_by": receipt.evaluated_by,
    }
    payload.update(overrides)
    return GovernedSegmentEvaluationReceipt._restore(**payload)


def _terminate_latest(
    snapshot: ExperimentGovernanceSnapshot,
    *,
    status: ExperimentAttemptStatus,
    occurred_at: datetime,
) -> ExperimentGovernanceSnapshot:
    attempt = snapshot.attempts[-1]
    terminal = NonExecutableTerminalEvidence.unsuccessful(
        attempt,
        status=status,
        reason_code=f"{status.value}_fixture",
        detail=f"Bounded {status.value} fixture evidence.",
    )
    return snapshot.transition_attempt(
        attempt.attempt_id,
        status=status,
        occurred_at=occurred_at,
        actor_id="phase3c-worker",
        terminal_evidence=terminal,
    )


def _completed_validation_snapshot(
    fixture: GovernanceFixture,
    *,
    requested_at: datetime = FIRST_ATTEMPT_AT,
) -> ExperimentGovernanceSnapshot:
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=requested_at,
    )
    return _complete_latest(
        queued,
        fixture,
        started_at=requested_at + timedelta(minutes=1),
        completed_at=requested_at + timedelta(minutes=2),
    )


def _revealed_snapshot(
    fixture: GovernanceFixture,
) -> ExperimentGovernanceSnapshot:
    completed = _completed_validation_snapshot(fixture)
    authorization = completed.create_holdout_authorization(
        selected_configuration_sha256=fixture.configuration.semantic_sha256,
        authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        authorized_by="holdout-custodian",
        access_reason="Run the single preselected final confirmation.",
    )
    return completed.reveal_holdout(authorization, fixture.test_certification)


def test_proof_types_reject_direct_construction() -> None:
    for proof_type in (
        StrategyConfigurationValidationReceipt,
        ExperimentSegmentEvidence,
        HoldoutCommitment,
        HoldoutRevealAuthorization,
        GovernedSegmentEvaluationReceipt,
        NonExecutableTerminalEvidence,
    ):
        with pytest.raises(TypeError, match="proof-constructed"):
            proof_type()


def test_segment_evidence_requires_exact_distinct_scoped_certification() -> None:
    fixture = _fixture()
    train = fixture.family.segment(EvaluationSegmentKind.TRAIN)
    full_certification = _scoped_certification(
        0,
        prices=("100", "102", "106", "99", "101"),
    )

    with pytest.raises(ExperimentGovernanceError, match="exact declared replay scope"):
        ExperimentSegmentEvidence.from_certification(train, full_certification)
    with pytest.raises(ExperimentGovernanceError, match="exact declared replay scope"):
        ExperimentSegmentEvidence.from_certification(
            replace(train, dataset_replay_sha256="f" * 64),
            fixture.train_certification,
        )
    with pytest.raises(ExperimentGovernanceError, match="train or validation"):
        ExperimentSegmentEvidence.from_certification(
            fixture.family.segment(EvaluationSegmentKind.TEST),
            fixture.test_certification,
        )

    replay_ids = tuple(segment.dataset_replay_sha256 for segment in fixture.family.segments)
    assert len(set(replay_ids)) == 3
    assert fixture.family.train_evidence.feature_certification_sha256 != (
        fixture.family.validation_evidence.feature_certification_sha256
    )

    validation_evidence = fixture.family.validation_evidence
    reused_source_tape = ExperimentSegmentEvidence._restore(
        segment=validation_evidence.segment,
        feature_certification_sha256=(validation_evidence.feature_certification_sha256),
        dataset_manifest_sha256=validation_evidence.dataset_manifest_sha256,
        source_tape_sha256=fixture.family.train_evidence.source_tape_sha256,
        replay_run_id=validation_evidence.replay_run_id,
        replay_manifest_sha256=validation_evidence.replay_manifest_sha256,
        replay_result_sha256=validation_evidence.replay_result_sha256,
        feature_artifact_sha256=validation_evidence.feature_artifact_sha256,
        feature_parity_receipt_sha256=(validation_evidence.feature_parity_receipt_sha256),
        feature_transcript_sha256=validation_evidence.feature_transcript_sha256,
        step_count=validation_evidence.step_count,
        snapshot_count=validation_evidence.snapshot_count,
    )
    with pytest.raises(ExperimentGovernanceError, match="distinct source tape"):
        replace(
            fixture.family,
            validation_evidence=reused_source_tape,
        )


def test_test_commitment_is_opaque_until_an_audited_reveal() -> None:
    fixture = _fixture()
    snapshot = ExperimentGovernanceSnapshot.empty(fixture.family)
    test_segment = fixture.family.segment(EvaluationSegmentKind.TEST)
    metadata_variant = HoldoutCommitment.from_certification(
        replace(test_segment, purge_before=timedelta(minutes=1)),
        fixture.test_certification,
    )
    alternate_configuration = _configuration(
        fixture.family.strategy_version,
        long_quantity="20",
    )
    ten_targets = _target_certification(
        fixture.test_certification,
        fixture.configuration,
    )
    twenty_targets = _target_certification(
        fixture.test_certification,
        alternate_configuration,
    )
    policy_neutral = HoldoutCommitment.from_certification(
        test_segment,
        twenty_targets.feature_certification,
    )

    assert not hasattr(fixture.family.test_commitment, "certification")
    assert not any(field.name.startswith("target_") for field in fields(HoldoutCommitment))
    assert ten_targets.semantic_sha256 != twenty_targets.semantic_sha256
    assert metadata_variant.content_commitment_sha256 == (
        fixture.family.test_commitment.content_commitment_sha256
    )
    assert policy_neutral == fixture.family.test_commitment
    assert policy_neutral.content_commitment_sha256 == (
        fixture.family.test_commitment.content_commitment_sha256
    )
    assert metadata_variant.semantic_sha256 != fixture.family.test_commitment.semantic_sha256
    with pytest.raises(ExperimentGovernanceError, match="remains sealed"):
        fixture.family.evidence(EvaluationSegmentKind.TEST)
    assert snapshot.holdout_reveal is None

    revealed = _revealed_snapshot(fixture)
    assert revealed.holdout_reveal is not None
    assert revealed.holdout_reveal.test_evidence.segment.kind is (EvaluationSegmentKind.TEST)
    assert revealed.holdout_reveal.test_evidence == (
        fixture.family.test_commitment.require_certification(
            fixture.family.segment(EvaluationSegmentKind.TEST),
            fixture.test_certification,
        )
    )


def test_schema_validation_receipt_binds_exact_version_payload_and_parameters() -> None:
    fixture = _fixture()
    repeated = StrategyConfigurationValidationReceipt.from_configuration(
        fixture.family.strategy_version,
        fixture.configuration,
        fixture.schema_payload,
    )

    assert repeated == fixture.validation
    assert repeated.configuration_sha256 == fixture.configuration.semantic_sha256
    assert repeated.parameter_schema_sha256 == (
        fixture.family.strategy_version.parameter_schema_sha256
    )
    with pytest.raises(
        ExperimentGovernanceError,
        match="registered parameter schema",
    ):
        StrategyConfigurationValidationReceipt.from_configuration(
            fixture.family.strategy_version,
            fixture.configuration,
            fixture.schema_payload + " ",
        )
    incomplete = StrategyConfigurationRecord(
        strategy_version_sha256=fixture.family.strategy_version.semantic_sha256,
        configuration_name="missing-required-lifetime",
        parameters={"long_quantity": Decimal("10")},
        registered_at=CONFIGURATION_REGISTERED_AT,
        registered_by="phase3c-owner",
    )
    with pytest.raises(ValueError, match="missing required"):
        StrategyConfigurationValidationReceipt.from_configuration(
            fixture.family.strategy_version,
            incomplete,
            fixture.schema_payload,
        )

    forged_parameters = StrategyConfigurationValidationReceipt._restore(
        strategy_version_sha256=fixture.family.strategy_version.semantic_sha256,
        configuration_sha256=fixture.configuration.semantic_sha256,
        parameter_schema_sha256=fixture.validation.parameter_schema_sha256,
        parameter_schema_payload=fixture.schema_payload,
        parameters_sha256="f" * 64,
    )
    with pytest.raises(ExperimentGovernanceError, match="exact configuration parameters"):
        _request(
            ExperimentGovernanceSnapshot.empty(fixture.family),
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT,
            validation=forged_parameters,
        )

    permissive_schema = (
        '{"additionalProperties":false,"properties":{"long_quantity":'
        '{"type":"string"}},"required":["long_quantity"],"type":"object"}'
    )
    forged_schema = StrategyConfigurationValidationReceipt._restore(
        strategy_version_sha256=fixture.family.strategy_version.semantic_sha256,
        configuration_sha256=incomplete.semantic_sha256,
        parameter_schema_sha256=hashlib.sha256(permissive_schema.encode("utf-8")).hexdigest(),
        parameter_schema_payload=permissive_schema,
        parameters_sha256=hashlib.sha256(
            canonical_json_bytes(tuple(incomplete.parameters.items()))
        ).hexdigest(),
    )
    with pytest.raises(ExperimentGovernanceError, match="family parameter schema"):
        _request(
            ExperimentGovernanceSnapshot.empty(fixture.family),
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT,
            configuration=incomplete,
            validation=forged_schema,
        )


def test_one_stable_attempt_identity_survives_the_full_lifecycle() -> None:
    fixture = _fixture()
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    attempt_id = queued.attempts[0].attempt_id
    running = queued.transition_attempt(
        attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    completed = _complete_latest(
        queued,
        fixture,
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )

    assert queued.attempts == running.attempts == completed.attempts
    assert completed.attempts[0].attempt_id == attempt_id
    assert [event.status for event in completed.lifecycle_events] == [
        ExperimentAttemptStatus.QUEUED,
        ExperimentAttemptStatus.RUNNING,
        ExperimentAttemptStatus.COMPLETED,
    ]
    assert [event.attempt_sequence_number for event in completed.lifecycle_events] == [
        0,
        1,
        2,
    ]
    assert len(completed.attempts) == 1


def test_budget_counts_stable_attempts_not_lifecycle_events() -> None:
    fixture = _fixture(maximum_trials=1)
    completed = _completed_validation_snapshot(fixture)

    assert len(completed.attempts) == 1
    assert len(completed.lifecycle_events) == 3
    with pytest.raises(ExperimentGovernanceError, match="budget"):
        _request(
            completed,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        )


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        (EvaluationSegmentKind.VALIDATION, ExperimentAttemptStatus.FAILED),
        (EvaluationSegmentKind.VALIDATION, ExperimentAttemptStatus.CANCELED),
        (EvaluationSegmentKind.VALIDATION, ExperimentAttemptStatus.ABANDONED),
        (EvaluationSegmentKind.TRAIN, ExperimentAttemptStatus.COMPLETED),
    ],
)
def test_only_completed_validation_can_be_selected_for_reveal(
    kind: EvaluationSegmentKind,
    status: ExperimentAttemptStatus,
) -> None:
    fixture = _fixture()
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=kind,
        requested_at=FIRST_ATTEMPT_AT,
    )
    if status is ExperimentAttemptStatus.COMPLETED:
        terminal = _complete_latest(
            queued,
            fixture,
            started_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        )
    else:
        terminal = _terminate_latest(
            queued,
            status=status,
            occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        )

    with pytest.raises(
        ExperimentGovernanceError,
        match="completed validation",
    ):
        terminal.create_holdout_authorization(
            selected_configuration_sha256=fixture.configuration.semantic_sha256,
            authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
            authorized_by="holdout-custodian",
            access_reason="An ineligible selection must fail.",
        )


def test_completed_validation_authorizes_and_opens_the_exact_holdout() -> None:
    fixture = _fixture()
    completed = _completed_validation_snapshot(fixture)
    authorization = completed.create_holdout_authorization(
        selected_configuration_sha256=fixture.configuration.semantic_sha256,
        authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        authorized_by="holdout-custodian",
        access_reason="Run the single final confirmation.",
    )
    revealed = completed.reveal_holdout(
        authorization,
        fixture.test_certification,
    )

    assert revealed.holdout_reveal is not None
    assert authorization.pre_reveal_snapshot_sha256 == completed.semantic_sha256
    assert authorization.pre_reveal_head_sha256 == completed.registry_head_sha256
    assert authorization.pre_reveal_attempts_sha256 == completed.attempts_sha256
    assert revealed.holdout_reveal.authorization == authorization
    assert revealed.holdout_reveal.previous_entry_sha256 == (completed.registry_head_sha256)
    assert revealed.registry_head_sha256 == revealed.holdout_reveal.semantic_sha256
    assert revealed.holdout_reveal.revealed_by == "holdout-custodian"

    wrong_test = _scoped_certification(20, lag=timedelta(seconds=31))
    with pytest.raises(ExperimentGovernanceError, match="does not open"):
        completed.reveal_holdout(authorization, wrong_test)


def test_snapshot_reconstruction_cannot_bypass_the_holdout_commitment() -> None:
    fixture = _fixture()
    completed = _completed_validation_snapshot(fixture)
    authorization = completed.create_holdout_authorization(
        selected_configuration_sha256=fixture.configuration.semantic_sha256,
        authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        authorized_by="holdout-custodian",
        access_reason="Run the single final confirmation.",
    )
    different_certification = _scoped_certification(
        20,
        lag=timedelta(seconds=31),
    )
    different_evidence = ExperimentSegmentEvidence._from_certification(
        fixture.family.segment(EvaluationSegmentKind.TEST),
        different_certification,
    )
    forged_reveal = AuditedHoldoutReveal(
        authorization=authorization,
        test_evidence=different_evidence,
        global_sequence_number=completed.next_global_sequence_number,
        previous_entry_sha256=completed.registry_head_sha256,
    )

    with pytest.raises(ExperimentGovernanceError, match="does not open"):
        ExperimentGovernanceSnapshot(
            family=completed.family,
            attempts=completed.attempts,
            lifecycle_events=completed.lifecycle_events,
            holdout_reveal=forged_reveal,
        )


def test_stale_authorization_fails_after_any_additional_completed_attempt() -> None:
    fixture = _fixture()
    first = _completed_validation_snapshot(fixture)
    stale = first.create_holdout_authorization(
        selected_configuration_sha256=fixture.configuration.semantic_sha256,
        authorized_at=FIRST_ATTEMPT_AT + timedelta(minutes=20),
        authorized_by="holdout-custodian",
        access_reason="This authorization will become stale.",
    )
    second_queued = _request(
        first,
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=10),
    )
    changed = _complete_latest(
        second_queued,
        fixture,
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=11),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=12),
    )

    with pytest.raises(ExperimentGovernanceError, match="current registry"):
        changed.reveal_holdout(stale, fixture.test_certification)


def test_post_reveal_policy_allows_one_selected_test_attempt_and_its_lifecycle() -> None:
    fixture = _fixture()
    revealed = _revealed_snapshot(fixture)
    assert revealed.holdout_reveal is not None

    with pytest.raises(ExperimentGovernanceError, match="forbidden after reveal"):
        _request(
            revealed,
            fixture,
            kind=EvaluationSegmentKind.TRAIN,
            requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
        )

    alternate = _configuration(
        fixture.family.strategy_version,
        long_quantity="20",
    )
    alternate_validation = StrategyConfigurationValidationReceipt.from_configuration(
        fixture.family.strategy_version,
        alternate,
        fixture.schema_payload,
    )
    with pytest.raises(ExperimentGovernanceError, match="selected validation"):
        _request(
            revealed,
            fixture,
            kind=EvaluationSegmentKind.TEST,
            requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
            configuration=alternate,
            validation=alternate_validation,
        )

    queued_test = _request(
        revealed,
        fixture,
        kind=EvaluationSegmentKind.TEST,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
    )
    test_attempt_id = queued_test.attempts[-1].attempt_id
    with pytest.raises(ExperimentGovernanceError, match="only one"):
        _request(
            queued_test,
            fixture,
            kind=EvaluationSegmentKind.TEST,
            requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=5),
        )
    completed = _complete_latest(
        queued_test,
        fixture,
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=5),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=6),
    )

    assert len(completed.attempts) == 2
    assert completed.attempts[-1].attempt_id == test_attempt_id
    assert completed.latest_event(test_attempt_id).status is (ExperimentAttemptStatus.COMPLETED)
    terminal = completed.latest_event(test_attempt_id).terminal_evidence
    assert type(terminal) is GovernedSegmentEvaluationReceipt
    assert terminal.source_evidence_sha256 == (
        completed.holdout_reveal.test_evidence.semantic_sha256
        if completed.holdout_reveal is not None
        else None
    )


def test_completed_terminal_evidence_is_a_configuration_bound_evaluation_receipt() -> None:
    fixture = _fixture()
    completed = _completed_validation_snapshot(fixture)
    terminal = completed.lifecycle_events[-1].terminal_evidence
    assert terminal is not None

    assert type(terminal) is GovernedSegmentEvaluationReceipt
    assert terminal.evidence_kind == GOVERNED_SEGMENT_EVALUATION
    assert terminal.configuration_sha256 == fixture.configuration.semantic_sha256
    assert terminal.feature_certification_sha256 == (
        fixture.validation_certification.semantic_sha256
    )
    assert terminal.started_at == FIRST_ATTEMPT_AT + timedelta(minutes=1)
    assert terminal.completed_at == FIRST_ATTEMPT_AT + timedelta(minutes=2)
    assert terminal.evaluated_by == "phase3c-worker"
    terminal_fields = {field.name for field in fields(GovernedSegmentEvaluationReceipt)}
    assert "strategy_code_sha256" not in terminal_fields
    assert not any(
        "report" in field_name
        or "pnl" in field_name
        or "promotion" in field_name
        or "fill" in field_name
        for field_name in terminal_fields
    )
    assert terminal.detail.startswith("Configuration-bound causal target evaluation")
    assert terminal.reason_code is None

    with pytest.raises(ExperimentGovernanceError, match="must be unsuccessful"):
        NonExecutableTerminalEvidence._restore(
            attempt_id=terminal.attempt_id,
            status=ExperimentAttemptStatus.COMPLETED,
            source_evidence_sha256=terminal.source_evidence_sha256,
            reason_code=None,
            detail="A digest-shaped completion claim.",
        )


def test_completion_rejects_wrong_policy_source_actor_and_time() -> None:
    fixture = _fixture()
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    attempt = queued.attempts[-1]
    running = queued.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    alternate = _configuration(
        fixture.family.strategy_version,
        long_quantity="20",
    )
    wrong_policy = _target_certification(
        fixture.validation_certification,
        alternate,
    )
    with pytest.raises(ExperimentGovernanceError, match="exact configuration"):
        running.complete_attempt(
            attempt.attempt_id,
            wrong_policy,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="phase3c-worker",
        )

    wrong_source = _target_certification(
        fixture.train_certification,
        fixture.configuration,
    )
    with pytest.raises(ExperimentGovernanceError, match="exact declared replay scope"):
        running.complete_attempt(
            attempt.attempt_id,
            wrong_source,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="phase3c-worker",
        )

    certification = _target_certification(
        fixture.validation_certification,
        fixture.configuration,
    )
    with pytest.raises(ExperimentGovernanceError, match="recorded running actor identifier"):
        running.complete_attempt(
            attempt.attempt_id,
            certification,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="different-worker",
        )
    with pytest.raises(ExperimentGovernanceError, match="must follow its running event"):
        running.complete_attempt(
            attempt.attempt_id,
            certification,
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
            actor_id="phase3c-worker",
        )


def test_non_executable_evidence_is_limited_to_unsuccessful_attempts() -> None:
    fixture = _fixture()
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    attempt = queued.attempts[-1]
    failed = NonExecutableTerminalEvidence.unsuccessful(
        attempt,
        status=ExperimentAttemptStatus.FAILED,
        reason_code="bounded_failure",
        detail="No target evaluation completed.",
    )
    assert failed.evidence_kind == NON_EXECUTABLE_DOMAIN_FIXTURE
    assert failed.source_evidence_sha256 is None
    assert failed.reason_code == "bounded_failure"

    running = queued.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    with pytest.raises(ExperimentGovernanceError, match="complete_attempt"):
        running.transition_attempt(
            attempt.attempt_id,
            status=ExperimentAttemptStatus.COMPLETED,
            occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="phase3c-worker",
            terminal_evidence=failed,
        )


@pytest.mark.parametrize(
    "altered_field",
    (
        "target_certification_sha256",
        "target_runtime_pin_sha256",
        "batch_result_sha256",
        "incremental_result_sha256",
        "target_parity_receipt_sha256",
        "target_transcript_sha256",
        "step_count",
        "target_count",
    ),
)
def test_supported_completion_rejects_caller_restored_target_provenance(
    altered_field: str,
) -> None:
    fixture = _fixture()
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
    )
    attempt = queued.attempts[-1]
    running = queued.transition_attempt(
        attempt.attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    certification = _target_certification(
        fixture.validation_certification,
        fixture.configuration,
    )
    completed_at = FIRST_ATTEMPT_AT + timedelta(minutes=2)
    completed = running.complete_attempt(
        attempt.attempt_id,
        certification,
        completed_at=completed_at,
        actor_id="phase3c-worker",
    )
    receipt = completed.lifecycle_events[-1].terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt

    if altered_field == "step_count":
        altered_value: object = receipt.step_count + 1
    elif altered_field == "target_count":
        altered_value = receipt.target_count - 1 if receipt.target_count else 1
    else:
        original = cast(str, getattr(receipt, altered_field))
        altered_value = "0" * 64 if original != "0" * 64 else "1" * 64
    forged = _restore_evaluation_receipt(receipt, **{altered_field: altered_value})
    assert forged.semantic_sha256 != receipt.semantic_sha256

    with pytest.raises(
        ExperimentGovernanceError,
        match="exact CertifiedFeatureTargetReplay",
    ):
        running.complete_attempt(
            attempt.attempt_id,
            cast(CertifiedFeatureTargetReplay, forged),
            completed_at=completed_at,
            actor_id="phase3c-worker",
        )
    with pytest.raises(ExperimentGovernanceError, match="complete_attempt"):
        running.transition_attempt(
            attempt.attempt_id,
            status=ExperimentAttemptStatus.COMPLETED,
            occurred_at=completed_at,
            actor_id="phase3c-worker",
            terminal_evidence=cast(Any, forged),
        )


def test_restored_completion_cannot_change_running_actor_context() -> None:
    fixture = _fixture()
    completed = _completed_validation_snapshot(fixture)
    receipt = completed.lifecycle_events[-1].terminal_evidence
    assert type(receipt) is GovernedSegmentEvaluationReceipt
    forged_running = replace(
        completed.lifecycle_events[-2],
        actor_id="forged-worker",
    )
    forged_completion = replace(
        completed.lifecycle_events[-1],
        previous_entry_sha256=forged_running.semantic_sha256,
    )
    with pytest.raises(ExperimentGovernanceError, match="governance context"):
        replace(
            completed,
            lifecycle_events=(
                completed.lifecycle_events[0],
                forged_running,
                forged_completion,
            ),
        )


def test_evaluation_configuration_rejects_out_of_bound_lifetime() -> None:
    fixture = _fixture()
    configuration = _configuration(
        fixture.family.strategy_version,
        target_lifetime_seconds=86_401,
    )
    validation = StrategyConfigurationValidationReceipt.from_configuration(
        fixture.family.strategy_version,
        configuration,
        fixture.schema_payload,
    )
    queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT,
        configuration=configuration,
        validation=validation,
    )
    running = queued.transition_attempt(
        queued.attempts[-1].attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    with pytest.raises(ExperimentGovernanceError, match="within the target bound"):
        running.complete_attempt(
            running.attempts[-1].attempt_id,
            _target_certification(
                fixture.validation_certification,
                fixture.configuration,
            ),
            completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
            actor_id="phase3c-worker",
        )


def test_configuration_specific_evaluations_share_only_feature_input() -> None:
    fixture = _fixture(maximum_trials=2)
    first = _completed_validation_snapshot(fixture)
    alternate = _configuration(
        fixture.family.strategy_version,
        long_quantity="20",
        target_lifetime_seconds=600,
    )
    alternate_validation = StrategyConfigurationValidationReceipt.from_configuration(
        fixture.family.strategy_version,
        alternate,
        fixture.schema_payload,
    )
    second_queued = _request(
        first,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=3),
        configuration=alternate,
        validation=alternate_validation,
    )
    second = _complete_latest(
        second_queued,
        fixture,
        started_at=FIRST_ATTEMPT_AT + timedelta(minutes=4),
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=5),
    )
    first_receipt = second.lifecycle_events[2].terminal_evidence
    second_receipt = second.lifecycle_events[-1].terminal_evidence
    assert type(first_receipt) is GovernedSegmentEvaluationReceipt
    assert type(second_receipt) is GovernedSegmentEvaluationReceipt
    assert first_receipt.source_evidence_sha256 == second_receipt.source_evidence_sha256
    assert first_receipt.feature_certification_sha256 == second_receipt.feature_certification_sha256
    assert first_receipt.configuration_sha256 != second_receipt.configuration_sha256
    assert first_receipt.target_policy_sha256 != second_receipt.target_policy_sha256
    assert first_receipt.target_certification_sha256 != second_receipt.target_certification_sha256


def test_unsuccessful_attempts_remain_in_the_authenticated_history() -> None:
    fixture = _fixture(maximum_trials=4)
    snapshot = ExperimentGovernanceSnapshot.empty(fixture.family)
    expected_statuses = (
        ExperimentAttemptStatus.FAILED,
        ExperimentAttemptStatus.CANCELED,
        ExperimentAttemptStatus.ABANDONED,
    )
    next_time = FIRST_ATTEMPT_AT
    for status in expected_statuses:
        snapshot = _request(
            snapshot,
            fixture,
            kind=EvaluationSegmentKind.VALIDATION,
            requested_at=next_time,
        )
        snapshot = _terminate_latest(
            snapshot,
            status=status,
            occurred_at=next_time + timedelta(minutes=1),
        )
        next_time += timedelta(minutes=2)

    assert len(snapshot.attempts) == 3
    assert tuple(event.status for event in snapshot.latest_events) == expected_statuses
    assert tuple(
        event.terminal_evidence.reason_code
        for event in snapshot.latest_events
        if event.terminal_evidence is not None
    ) == tuple(f"{status.value}_fixture" for status in expected_statuses)
    assert [event.global_sequence_number for event in snapshot.lifecycle_events] == list(
        range(len(snapshot.lifecycle_events))
    )


def test_history_is_immutable_hash_stable_and_rejects_a_forged_chain() -> None:
    fixture = _fixture()
    first = _completed_validation_snapshot(fixture)
    repeated = _completed_validation_snapshot(fixture)

    assert EXPERIMENT_GOVERNANCE_CONTRACT_VERSION == ("phase3-experiment-governance-v2")
    assert EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION == ("phase3-segment-evaluation-v1")
    assert first == repeated
    assert first.semantic_sha256 == repeated.semantic_sha256
    assert first.canonical_json == repeated.canonical_json
    with pytest.raises(FrozenInstanceError):
        first.snapshot_sha256 = "f" * 64  # type: ignore[misc]

    forged_last = replace(
        first.lifecycle_events[-1],
        previous_entry_sha256="f" * 64,
    )
    with pytest.raises(ExperimentGovernanceError, match="predecessor chain"):
        replace(
            first,
            lifecycle_events=(*first.lifecycle_events[:-1], forged_last),
        )

    first_queued = _request(
        ExperimentGovernanceSnapshot.empty(fixture.family),
        fixture,
        kind=EvaluationSegmentKind.TRAIN,
        requested_at=FIRST_ATTEMPT_AT,
    )
    first_running = first_queued.transition_attempt(
        first_queued.attempts[-1].attempt_id,
        status=ExperimentAttemptStatus.RUNNING,
        occurred_at=FIRST_ATTEMPT_AT + timedelta(minutes=1),
        actor_id="phase3c-worker",
    )
    second_queued = _request(
        first_running,
        fixture,
        kind=EvaluationSegmentKind.VALIDATION,
        requested_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
    )
    event_zero, event_one, event_two = second_queued.lifecycle_events
    with pytest.raises(ExperimentGovernanceError, match="global sequence order"):
        replace(
            second_queued,
            lifecycle_events=(event_zero, event_two, event_one),
        )

    forged_queued_event = replace(
        first_queued.lifecycle_events[0],
        actor_id="forged-requester",
    )
    with pytest.raises(ExperimentGovernanceError, match="stable requester"):
        replace(
            first_queued,
            lifecycle_events=(forged_queued_event,),
        )
