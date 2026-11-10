from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import pytest

from packages.domain.experiment_registry import (
    EvaluationSegment,
    EvaluationSegmentKind,
    ExperimentDatasetReplayPin,
    ExperimentEvaluationPlan,
    ExperimentFamily,
    ExperimentFamilyRegistry,
    ExperimentTrial,
    ExperimentTrialStatus,
    FixtureSourceKind,
    FrozenPromotionCriteria,
    PromotionComparison,
    PromotionCriterion,
    StrategyConfigurationRecord,
    StrategyVersionRecord,
)

DATA_START = datetime(2025, 1, 1, tzinfo=UTC)
TRAIN_END = datetime(2025, 1, 31, 23, 59, tzinfo=UTC)
VALIDATION_START = datetime(2025, 2, 1, tzinfo=UTC)
VALIDATION_END = datetime(2025, 2, 28, 23, 59, tzinfo=UTC)
TEST_START = datetime(2025, 3, 1, tzinfo=UTC)
TEST_END = datetime(2025, 3, 31, 23, 59, tzinfo=UTC)
DATA_END = datetime(2025, 4, 1, tzinfo=UTC)
REPLAY_COMPLETED_AT = datetime(2026, 7, 1, 9, tzinfo=UTC)
STRATEGY_REGISTERED_AT = datetime(2026, 7, 1, 10, tzinfo=UTC)
FAMILY_CREATED_AT = datetime(2026, 7, 2, 10, tzinfo=UTC)
CRITERIA_FROZEN_AT = FAMILY_CREATED_AT + timedelta(hours=1)
CONFIGURATION_REGISTERED_AT = FAMILY_CREATED_AT + timedelta(hours=2)
FIRST_TRIAL_AT = FAMILY_CREATED_AT + timedelta(days=1)
HOLDOUT_REVEALED_AT = FAMILY_CREATED_AT + timedelta(days=2)


def strategy_version() -> StrategyVersionRecord:
    return StrategyVersionRecord(
        strategy_id="fixture-momentum",
        strategy_version="1.0.0",
        code_sha256="1" * 64,
        parameter_schema_sha256="2" * 64,
        state_schema_version="momentum-state-v1",
        source_revision="3" * 40,
        registered_at=STRATEGY_REGISTERED_AT,
        registered_by="research-owner",
    )


def configuration(
    parameters: dict[str, object] | None = None,
) -> StrategyConfigurationRecord:
    return StrategyConfigurationRecord(
        strategy_version_sha256=strategy_version().semantic_sha256,
        configuration_name="lookback-20",
        parameters=parameters
        or {
            "enabled": True,
            "lookback": Decimal("20"),
            "minimum_return": Decimal("0.01"),
        },
        registered_at=CONFIGURATION_REGISTERED_AT,
        registered_by="research-owner",
    )


def dataset_replay() -> ExperimentDatasetReplayPin:
    return ExperimentDatasetReplayPin(
        source_id="recorded-fixture-2025q1",
        source_kind=FixtureSourceKind.RECORDED,
        price_basis="raw",
        dataset_manifest_sha256="4" * 64,
        source_tape_sha256="5" * 64,
        replay_run_id="6" * 64,
        replay_manifest_sha256="6" * 64,
        replay_input_sha256="7" * 64,
        replay_semantic_sha256="8" * 64,
        coverage_start=DATA_START,
        coverage_end=DATA_END,
        replay_completed_at=REPLAY_COMPLETED_AT,
    )


def evaluation_plan(
    dataset: ExperimentDatasetReplayPin | None = None,
) -> ExperimentEvaluationPlan:
    dataset = dataset or dataset_replay()
    return ExperimentEvaluationPlan(
        plan_version="chronological-fixture-v1",
        segments=(
            EvaluationSegment(
                kind=EvaluationSegmentKind.TRAIN,
                coverage_start=DATA_START,
                coverage_end=TRAIN_END,
                dataset_replay_sha256=dataset.semantic_sha256,
                embargo_after=timedelta(minutes=1),
            ),
            EvaluationSegment(
                kind=EvaluationSegmentKind.VALIDATION,
                coverage_start=VALIDATION_START,
                coverage_end=VALIDATION_END,
                dataset_replay_sha256=dataset.semantic_sha256,
                purge_before=timedelta(minutes=1),
                embargo_after=timedelta(minutes=1),
            ),
            EvaluationSegment(
                kind=EvaluationSegmentKind.TEST,
                coverage_start=TEST_START,
                coverage_end=TEST_END,
                dataset_replay_sha256=dataset.semantic_sha256,
                purge_before=timedelta(minutes=1),
            ),
        ),
    )


def promotion_criteria(*, maximum_trials: int = 5) -> FrozenPromotionCriteria:
    return FrozenPromotionCriteria(
        criteria_version="fixture-promotion-v1",
        criteria=(
            PromotionCriterion(
                metric_name="maximum_drawdown",
                comparison=PromotionComparison.LESS_THAN_OR_EQUAL,
                threshold=Decimal("0.10"),
                minimum_observations=20,
            ),
            PromotionCriterion(
                metric_name="total_return",
                comparison=PromotionComparison.GREATER_THAN_OR_EQUAL,
                threshold=Decimal("0.02"),
                minimum_observations=20,
            ),
        ),
        selection_rule="Highest validation return among candidates passing the drawdown limit.",
        multiple_testing_method="holm-bonferroni-v1",
        maximum_pre_holdout_trials=maximum_trials,
        frozen_at=CRITERIA_FROZEN_AT,
        frozen_by="research-owner",
    )


def family(*, maximum_trials: int = 5) -> ExperimentFamily:
    dataset = dataset_replay()
    return ExperimentFamily(
        family_name="fixture-momentum-q1",
        hypothesis="Positive one-month momentum persists after declared costs.",
        owner_id="research-owner",
        created_at=FAMILY_CREATED_AT,
        strategy_version=strategy_version(),
        dataset_replay=dataset,
        evaluation_plan=evaluation_plan(dataset),
        promotion_criteria=promotion_criteria(maximum_trials=maximum_trials),
    )


def trial(
    experiment_family: ExperimentFamily,
    *,
    sequence: int,
    segment_kind: EvaluationSegmentKind,
    status: ExperimentTrialStatus,
    requested_at: datetime | None = None,
    holdout_reveal_sha256: str | None = None,
    trial_configuration: StrategyConfigurationRecord | None = None,
) -> ExperimentTrial:
    requested_at = requested_at or FIRST_TRIAL_AT + timedelta(hours=sequence)
    started_at: datetime | None = requested_at + timedelta(minutes=1)
    finished_at: datetime | None = requested_at + timedelta(minutes=2)
    run_manifest_sha256: str | None = None
    reason_code: str | None = None
    reason_sha256: str | None = None
    if status is ExperimentTrialStatus.QUEUED:
        started_at = None
        finished_at = None
    elif status is ExperimentTrialStatus.RUNNING:
        finished_at = None
    elif status is ExperimentTrialStatus.COMPLETED:
        run_manifest_sha256 = "9" * 64
    else:
        reason_code = f"{status.value}_fixture"
        reason_sha256 = "a" * 64
        if status is ExperimentTrialStatus.CANCELED:
            started_at = None
    return ExperimentTrial(
        sequence=sequence,
        attempt_number=sequence + 1,
        family_id=experiment_family.family_id,
        configuration=trial_configuration or configuration(),
        segment_kind=segment_kind,
        segment_sha256=experiment_family.evaluation_plan.segment(segment_kind).semantic_sha256,
        status=status,
        requested_at=requested_at,
        started_at=started_at,
        finished_at=finished_at,
        run_manifest_sha256=run_manifest_sha256,
        terminal_reason_code=reason_code,
        terminal_reason_sha256=reason_sha256,
        holdout_reveal_sha256=holdout_reveal_sha256,
    )


def pre_reveal_registry() -> ExperimentFamilyRegistry:
    experiment_family = family()
    return ExperimentFamilyRegistry(
        family=experiment_family,
        trials=(
            trial(
                experiment_family,
                sequence=0,
                segment_kind=EvaluationSegmentKind.TRAIN,
                status=ExperimentTrialStatus.COMPLETED,
            ),
            trial(
                experiment_family,
                sequence=1,
                segment_kind=EvaluationSegmentKind.VALIDATION,
                status=ExperimentTrialStatus.FAILED,
            ),
            trial(
                experiment_family,
                sequence=2,
                segment_kind=EvaluationSegmentKind.VALIDATION,
                status=ExperimentTrialStatus.CANCELED,
            ),
        ),
    )


def revealed_registry() -> ExperimentFamilyRegistry:
    return pre_reveal_registry().with_holdout_reveal(
        revealed_at=HOLDOUT_REVEALED_AT,
        revealed_by="holdout-custodian",
        access_reason="Evaluate the frozen promotion criteria once.",
        authorization_sha256="b" * 64,
        selected_configuration_sha256=configuration().semantic_sha256,
    )


def completed_registry() -> ExperimentFamilyRegistry:
    registry = revealed_registry()
    assert registry.holdout_reveal is not None
    return registry.with_trial(
        trial(
            registry.family,
            sequence=3,
            segment_kind=EvaluationSegmentKind.TEST,
            status=ExperimentTrialStatus.COMPLETED,
            requested_at=HOLDOUT_REVEALED_AT + timedelta(hours=1),
            holdout_reveal_sha256=registry.holdout_reveal.semantic_sha256,
        )
    )


def test_strategy_records_are_canonical_bounded_and_immutable() -> None:
    first = configuration(
        {
            "lookback": Decimal("20.00"),
            "enabled": True,
            "minimum_return": Decimal("0.010"),
        }
    )
    second = configuration(
        {
            "minimum_return": Decimal("0.01"),
            "enabled": True,
            "lookback": Decimal("20"),
        }
    )

    assert first == second
    assert first.configuration_id == first.configuration_sha256
    assert first.parameters["lookback"] == Decimal("20")
    assert strategy_version().strategy_version_id == strategy_version().semantic_sha256
    with pytest.raises(TypeError):
        first.parameters["lookback"] = Decimal("21")  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        first.configuration_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(ValueError, match="null, bool, int, str, or Decimal"):
        configuration({"lookback": 20.0})
    with pytest.raises(ValueError, match="finite"):
        configuration({"lookback": Decimal("Infinity")})
    with pytest.raises(ValueError, match="source commit digest"):
        replace(strategy_version(), source_revision="main")


def test_dataset_pin_is_fixture_only_raw_and_sealed() -> None:
    pin = dataset_replay()

    assert pin.source_kind is FixtureSourceKind.RECORDED
    assert len(pin.semantic_sha256) == 64
    with pytest.raises(ValueError, match="fixture source kind"):
        replace(pin, source_kind="vendor")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="raw prices"):
        replace(pin, price_basis="adjusted")
    with pytest.raises(ValueError, match="content-addressed manifest"):
        replace(pin, replay_run_id="f" * 64)
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(pin, coverage_start=DATA_START.replace(tzinfo=None))
    with pytest.raises(ValueError, match="must follow"):
        replace(pin, coverage_end=pin.coverage_start)


def test_evaluation_plan_requires_exact_chronological_train_validation_test() -> None:
    plan = evaluation_plan()

    assert plan.train.kind is EvaluationSegmentKind.TRAIN
    assert plan.validation.kind is EvaluationSegmentKind.VALIDATION
    assert plan.test.kind is EvaluationSegmentKind.TEST
    assert plan.segment(EvaluationSegmentKind.TEST) == plan.test
    with pytest.raises(ValueError, match="ordered train, validation, and test"):
        replace(plan, segments=(plan.validation, plan.train, plan.test))
    with pytest.raises(ValueError, match="must not overlap"):
        replace(
            plan,
            segments=(
                replace(plan.train, coverage_end=plan.validation.coverage_start),
                plan.validation,
                plan.test,
            ),
        )
    with pytest.raises(ValueError, match="share one dataset"):
        replace(
            plan,
            segments=(
                plan.train,
                replace(plan.validation, dataset_replay_sha256="f" * 64),
                plan.test,
            ),
        )
    with pytest.raises(ValueError, match="non-negative exact timedelta"):
        replace(plan.train, purge_before=timedelta(microseconds=-1))


def test_family_binds_inputs_coverage_and_frozen_criteria() -> None:
    experiment_family = family()

    assert experiment_family.family_id == experiment_family.family_sha256
    assert len(experiment_family.family_sha256) == 64
    with pytest.raises(ValueError, match="registered before"):
        replace(
            experiment_family,
            strategy_version=replace(
                experiment_family.strategy_version,
                registered_at=experiment_family.created_at + timedelta(microseconds=1),
            ),
        )
    with pytest.raises(ValueError, match="cannot be frozen before"):
        replace(
            experiment_family,
            promotion_criteria=replace(
                experiment_family.promotion_criteria,
                frozen_at=experiment_family.created_at - timedelta(microseconds=1),
            ),
        )
    outside_plan = replace(
        experiment_family.evaluation_plan,
        segments=(
            replace(
                experiment_family.evaluation_plan.train,
                coverage_start=DATA_START - timedelta(microseconds=1),
            ),
            experiment_family.evaluation_plan.validation,
            experiment_family.evaluation_plan.test,
        ),
    )
    with pytest.raises(ValueError, match="inside dataset coverage"):
        replace(experiment_family, evaluation_plan=outside_plan)


def test_promotion_gate_is_ordered_exact_and_bounded_before_reveal() -> None:
    criteria = promotion_criteria()

    assert len(criteria.semantic_sha256) == 64
    assert criteria.maximum_pre_holdout_trials == 5
    with pytest.raises(ValueError, match="canonically ordered"):
        replace(criteria, criteria=tuple(reversed(criteria.criteria)))
    with pytest.raises(ValueError, match="canonically ordered"):
        replace(criteria, criteria=(criteria.criteria[0], criteria.criteria[0]))
    with pytest.raises(ValueError, match="exact Decimal"):
        replace(criteria.criteria[0], threshold=0.10)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        replace(criteria, maximum_pre_holdout_trials=0)


@pytest.mark.parametrize(
    "status",
    [
        ExperimentTrialStatus.FAILED,
        ExperimentTrialStatus.CANCELED,
        ExperimentTrialStatus.ABANDONED,
    ],
)
def test_registry_retains_unsuccessful_attempts_with_terminal_evidence(
    status: ExperimentTrialStatus,
) -> None:
    experiment_family = family()
    unsuccessful = trial(
        experiment_family,
        sequence=0,
        segment_kind=EvaluationSegmentKind.VALIDATION,
        status=status,
    )
    registry = ExperimentFamilyRegistry(family=experiment_family, trials=(unsuccessful,))

    assert registry.trials[0].status is status
    assert registry.trials[0].terminal_reason_code == f"{status.value}_fixture"
    assert registry.trials[0].terminal_reason_sha256 == "a" * 64
    assert len(registry.trials[0].semantic_sha256) == 64


def test_trial_lifecycle_snapshots_keep_input_identity_and_change_outcome_identity() -> None:
    experiment_family = family()
    queued = trial(
        experiment_family,
        sequence=0,
        segment_kind=EvaluationSegmentKind.TRAIN,
        status=ExperimentTrialStatus.QUEUED,
    )
    running = replace(
        queued,
        status=ExperimentTrialStatus.RUNNING,
        started_at=queued.requested_at + timedelta(minutes=1),
    )
    completed = replace(
        running,
        status=ExperimentTrialStatus.COMPLETED,
        finished_at=queued.requested_at + timedelta(minutes=2),
        run_manifest_sha256="9" * 64,
    )

    assert queued.trial_id == running.trial_id == completed.trial_id
    assert len({queued.trial_sha256, running.trial_sha256, completed.trial_sha256}) == 3
    with pytest.raises(ValueError, match="terminal trial requires"):
        replace(running, status=ExperimentTrialStatus.FAILED)
    with pytest.raises(ValueError, match="completed trial requires"):
        replace(completed, run_manifest_sha256=None)
    with pytest.raises(ValueError, match="queued trial"):
        replace(completed, status=ExperimentTrialStatus.QUEUED)


def test_holdout_reveal_binds_frozen_gate_and_every_pre_reveal_trial() -> None:
    pre_reveal = pre_reveal_registry()
    revealed = revealed_registry()
    completed = completed_registry()

    assert revealed.holdout_reveal is not None
    assert revealed.holdout_reveal.pre_reveal_trial_count == 3
    assert revealed.holdout_reveal.promotion_criteria_sha256 == (
        revealed.family.promotion_criteria.semantic_sha256
    )
    assert revealed.holdout_reveal.selected_configuration_sha256 == (
        configuration().semantic_sha256
    )
    assert completed.trials[-1].segment_kind is EvaluationSegmentKind.TEST
    assert completed.trials[-1].holdout_reveal_sha256 == (revealed.holdout_reveal.semantic_sha256)
    assert completed.registry_sha256 == completed_registry().registry_sha256
    assert completed.canonical_json == completed_registry().canonical_json
    assert pre_reveal.registry_sha256 != revealed.registry_sha256
    assert revealed.registry_sha256 != completed.registry_sha256


def test_final_test_access_fails_closed_before_or_outside_exact_reveal() -> None:
    experiment_family = family()
    forged_test = trial(
        experiment_family,
        sequence=0,
        segment_kind=EvaluationSegmentKind.TEST,
        status=ExperimentTrialStatus.COMPLETED,
        holdout_reveal_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="forbidden before holdout reveal"):
        ExperimentFamilyRegistry(family=experiment_family, trials=(forged_test,))

    revealed = revealed_registry()
    assert revealed.holdout_reveal is not None
    with pytest.raises(ValueError, match="exact holdout reveal"):
        revealed.with_trial(
            trial(
                revealed.family,
                sequence=3,
                segment_kind=EvaluationSegmentKind.TEST,
                status=ExperimentTrialStatus.COMPLETED,
                requested_at=HOLDOUT_REVEALED_AT + timedelta(hours=1),
                holdout_reveal_sha256="f" * 64,
            )
        )
    with pytest.raises(ValueError, match="cannot add exploratory trials"):
        revealed.with_trial(
            trial(
                revealed.family,
                sequence=3,
                segment_kind=EvaluationSegmentKind.VALIDATION,
                status=ExperimentTrialStatus.COMPLETED,
                requested_at=HOLDOUT_REVEALED_AT + timedelta(hours=1),
            )
        )
    forged_reveal = replace(revealed.holdout_reveal, pre_reveal_trials_sha256="f" * 64)
    with pytest.raises(ValueError, match="exact pre-reveal trials"):
        replace(revealed, holdout_reveal=forged_reveal)


def test_trials_cannot_run_before_the_promotion_gate_is_frozen() -> None:
    original = family()
    late_gate = replace(
        original.promotion_criteria,
        frozen_at=CONFIGURATION_REGISTERED_AT + timedelta(hours=1),
    )
    experiment_family = replace(original, promotion_criteria=late_gate)
    premature = trial(
        experiment_family,
        sequence=0,
        segment_kind=EvaluationSegmentKind.VALIDATION,
        status=ExperimentTrialStatus.COMPLETED,
        requested_at=CONFIGURATION_REGISTERED_AT + timedelta(minutes=30),
    )

    with pytest.raises(ValueError, match="before promotion criteria are frozen"):
        ExperimentFamilyRegistry(family=experiment_family, trials=(premature,))


def test_holdout_reveal_freezes_one_preselected_configuration_and_one_test() -> None:
    pre_reveal = pre_reveal_registry()
    with pytest.raises(ValueError, match="select a configuration"):
        pre_reveal.with_holdout_reveal(
            revealed_at=HOLDOUT_REVEALED_AT,
            revealed_by="holdout-custodian",
            access_reason="Attempt an untried candidate.",
            authorization_sha256="b" * 64,
            selected_configuration_sha256="f" * 64,
        )

    revealed = revealed_registry()
    assert revealed.holdout_reveal is not None
    adapted_configuration = configuration(
        {
            "enabled": True,
            "lookback": Decimal("21"),
            "minimum_return": Decimal("0.01"),
        }
    )
    with pytest.raises(ValueError, match="configuration selected before holdout reveal"):
        revealed.with_trial(
            trial(
                revealed.family,
                sequence=3,
                segment_kind=EvaluationSegmentKind.TEST,
                status=ExperimentTrialStatus.COMPLETED,
                requested_at=HOLDOUT_REVEALED_AT + timedelta(hours=1),
                holdout_reveal_sha256=revealed.holdout_reveal.semantic_sha256,
                trial_configuration=adapted_configuration,
            )
        )

    completed = completed_registry()
    assert completed.holdout_reveal is not None
    with pytest.raises(ValueError, match="only one selected-configuration trial"):
        completed.with_trial(
            trial(
                completed.family,
                sequence=4,
                segment_kind=EvaluationSegmentKind.TEST,
                status=ExperimentTrialStatus.COMPLETED,
                requested_at=HOLDOUT_REVEALED_AT + timedelta(hours=2),
                holdout_reveal_sha256=completed.holdout_reveal.semantic_sha256,
            )
        )


def test_reveal_requires_finished_trials_budget_and_strictly_prior_frozen_gate() -> None:
    experiment_family = family()
    active_registry = ExperimentFamilyRegistry(
        family=experiment_family,
        trials=(
            trial(
                experiment_family,
                sequence=0,
                segment_kind=EvaluationSegmentKind.TRAIN,
                status=ExperimentTrialStatus.RUNNING,
            ),
        ),
    )
    with pytest.raises(ValueError, match="while exploratory trials are active"):
        active_registry.with_holdout_reveal(
            revealed_at=HOLDOUT_REVEALED_AT,
            revealed_by="custodian",
            access_reason="Premature reveal",
            authorization_sha256="b" * 64,
            selected_configuration_sha256=configuration().semantic_sha256,
        )

    with pytest.raises(ValueError, match="frozen before holdout reveal"):
        ExperimentFamilyRegistry.empty(experiment_family).with_holdout_reveal(
            revealed_at=experiment_family.promotion_criteria.frozen_at,
            revealed_by="custodian",
            access_reason="Same-instant reveal",
            authorization_sha256="b" * 64,
            selected_configuration_sha256=configuration().semantic_sha256,
        )

    limited_family = family(maximum_trials=1)
    with pytest.raises(ValueError, match="trial budget"):
        ExperimentFamilyRegistry(
            family=limited_family,
            trials=(
                trial(
                    limited_family,
                    sequence=0,
                    segment_kind=EvaluationSegmentKind.TRAIN,
                    status=ExperimentTrialStatus.COMPLETED,
                ),
                trial(
                    limited_family,
                    sequence=1,
                    segment_kind=EvaluationSegmentKind.VALIDATION,
                    status=ExperimentTrialStatus.FAILED,
                ),
            ),
        )


def test_registry_identity_ignores_ambient_decimal_context() -> None:
    with localcontext() as decimal_context:
        decimal_context.prec = 3
        low_precision = completed_registry()
    with localcontext() as decimal_context:
        decimal_context.prec = 40
        high_precision = completed_registry()

    assert low_precision == high_precision
    assert low_precision.registry_sha256 == high_precision.registry_sha256
    assert low_precision.family.family_id == high_precision.family.family_id
