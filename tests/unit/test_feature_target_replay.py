from __future__ import annotations

from copy import copy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.feature import (
    AuthenticatedFeatureReplayInput,
    FeatureArtifact,
)
from packages.domain.feature_replay import (
    certify_rolling_close_mean_parity,
    create_rolling_close_mean_artifact,
)
from packages.domain.feature_target import (
    CertifiedFeatureTargetReplay,
    FeatureDecisionContext,
    FeatureNotAvailableError,
    FeatureTargetDecision,
    FeatureTargetParityError,
    FeatureTargetParityReceipt,
    FeatureTargetReplayResult,
    FeatureTargetRuntimePin,
    FeatureTargetStepStatus,
    FeatureVisibilityProof,
    RollingCloseMeanTargetPolicy,
)
from packages.domain.feature_target_replay import (
    RollingCloseMeanTargetIncrementalState,
    certify_rolling_close_mean_target_parity,
    replay_rolling_close_mean_targets_batch,
    replay_rolling_close_mean_targets_incremental,
)
from packages.domain.market_batch import MarketWatermark, ReplayRevisionPolicy
from packages.domain.models import MarketEvent
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.replay import ReplayResult, replay_market_events
from packages.domain.replay_manifest import (
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayPlanPin,
    ReplayRunManifest,
    RuntimePin,
)

BASE = datetime(2026, 7, 21, 14, 30, tzinfo=UTC)
MANIFEST_SHA256 = "1" * 64
MANIFEST_TAPE_SHA256 = "2" * 64
IMPLEMENTATION_SHA256 = "4" * 64


def _event(
    index: int,
    price: str,
    *,
    instrument_id: str = "aqt-security-spy",
    symbol: str = "SPY",
) -> MarketEvent:
    event_time = BASE + timedelta(minutes=index)
    return MarketEvent(
        event_id=f"{instrument_id}-event-{index}",
        instrument_id=instrument_id,
        symbol=symbol,
        event_time=event_time,
        available_at=event_time + timedelta(seconds=1),
        close_price=Decimal(price),
        source="phase3b-fixture",
        source_sequence=index,
    )


def _watermark(
    index: int,
    *,
    instruments: tuple[str, ...] = ("aqt-security-spy",),
) -> MarketWatermark:
    event_time = BASE + timedelta(minutes=index)
    return MarketWatermark(
        watermark_id=f"phase3b-watermark-{index}",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=5),
        expected_instrument_ids=instruments,
        revision_policy=ReplayRevisionPolicy.REVISED_AS_OF,
    )


def _replay(
    prices: tuple[str | None, ...] = ("100", "102", "106", "99"),
    *,
    events: tuple[MarketEvent, ...] | None = None,
    watermarks: tuple[MarketWatermark, ...] | None = None,
) -> ReplayResult:
    pinned_watermarks = watermarks or tuple(_watermark(index) for index in range(len(prices)))
    pinned_events = events or tuple(
        _event(index, price) for index, price in enumerate(prices) if price is not None
    )
    return replay_market_events(events=pinned_events, watermarks=pinned_watermarks)


def _artifact(
    replay: ReplayResult,
    *,
    lag: timedelta = timedelta(seconds=30),
) -> FeatureArtifact:
    expected_instrument_ids = tuple(
        sorted(
            {
                instrument_id
                for batch in replay.batches
                for instrument_id in batch.watermark.expected_instrument_ids
            }
        )
    )
    row_count = len(replay.processed_event_ids)
    partition_object_sha256 = "5" * 64
    dataset = DatasetPin(
        manifest_id=MANIFEST_SHA256,
        manifest_sha256=MANIFEST_SHA256,
        source_tape_sha256=MANIFEST_TAPE_SHA256,
        source_id="phase3b-fixture",
        source_kind="synthetic_fixture",
        schema_version="raw-bar-v1",
        price_basis="raw",
        revision_policy=ReplayRevisionPolicy.REVISED_AS_OF,
        calendar_version="phase3b-calendar-v1",
        calendar_sha256="6" * 64,
        calendar_hash_version="input-v1",
        tzdata_version="2026a",
        universe_version="phase3b-universe-v1",
        universe_sha256="7" * 64,
        universe_hash_version="input-v1",
        corporate_action_version="phase3b-actions-v1",
        corporate_action_sha256="8" * 64,
        corporate_action_hash_version="input-v1",
        row_count=row_count,
        partitions=(
            DatasetPartitionPin(
                ordinal=0,
                partition_id="9" * 64,
                object_id=partition_object_sha256,
                object_key=(
                    f"normalized/sha256/{partition_object_sha256[:2]}/"
                    f"{partition_object_sha256}.parquet"
                ),
                format="parquet",
                byte_sha256=partition_object_sha256,
                semantic_sha256="a" * 64,
                semantic_checksum_version="input-v1",
                size_bytes=1024,
                row_count=row_count,
                event_time_start=replay.batches[0].watermark.event_time_through,
                event_time_end=replay.batches[-1].watermark.event_time_through,
                available_at_start=replay.started_at,
                available_at_end=replay.completed_at,
            ),
        ),
    )
    first_watermark = replay.batches[0].watermark
    plan = ReplayPlanPin(
        coverage_start=first_watermark.event_time_through,
        coverage_end=replay.batches[-1].watermark.event_time_through,
        interval="1m",
        decision_lag=first_watermark.closed_at - first_watermark.event_time_through,
        revision_policy=ReplayRevisionPolicy.REVISED_AS_OF,
        missing_data_policy=first_watermark.missing_data_policy,
        late_event_policy=first_watermark.late_event_policy,
        expected_instrument_ids=expected_instrument_ids,
        watermark_count=len(replay.batches),
        watermarks_sha256="b" * 64,
    )
    manifest = ReplayRunManifest.from_replay_result(
        dataset=dataset,
        plan=plan,
        engine=EnginePin(
            tape_adapter_version="phase3b-unit-tape-v1",
            watermark_policy_version="phase3b-unit-watermark-v1",
        ),
        runtime=RuntimePin(
            source_revision="c" * 40,
            dirty_patch_sha256="d" * 64,
            dependency_lock_sha256="e" * 64,
            schema_revision="phase3b-unit",
            python_version="3.12",
            pyarrow_version="21",
        ),
        result=replay,
        source_tape_sha256=MANIFEST_TAPE_SHA256,
    )
    source = AuthenticatedFeatureReplayInput._from_verified_manifest_tape(
        manifest=manifest,
        replay=replay,
    )
    return create_rolling_close_mean_artifact(
        source=source,
        implementation_sha256=IMPLEMENTATION_SHA256,
        publication_lag=lag,
    )


def _certify(
    replay: ReplayResult,
    *,
    lag: timedelta = timedelta(seconds=30),
    quantity: str = "10",
) -> CertifiedFeatureTargetReplay:
    feature = certify_rolling_close_mean_parity(_artifact(replay, lag=lag), replay)
    return certify_rolling_close_mean_target_parity(
        feature,
        RollingCloseMeanTargetPolicy(long_quantity=Decimal(quantity)),
    )


def test_independent_paths_certify_exact_causal_target_parity() -> None:
    certified = _certify(_replay())

    assert certified.batch_result.steps == certified.incremental_result.steps
    assert certified.batch_result.transcript_sha256 == (
        certified.incremental_result.transcript_sha256
    )
    assert [step.status for step in certified.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
        FeatureTargetStepStatus.READY,
    ]
    assert [target.targets[0].quantity for target in certified.batch_result.targets] == [
        Decimal("10"),
        Decimal("0"),
    ]
    first_decision = certified.batch_result.decisions[0]
    assert first_decision.context.feature_snapshot_ids == (
        certified.feature_certification.batch_result.snapshots[0].snapshot_id,
    )
    assert first_decision.target.strategy_configuration_sha256 == (
        certified.runtime_pin.strategy_configuration_sha256
    )
    assert certified.receipt.feature_parity_receipt_sha256 == (
        certified.feature_certification.receipt.semantic_sha256
    )
    assert certified.receipt.target_ids == tuple(
        target.target_id for target in certified.batch_result.targets
    )
    assert certified.receipt.target_count == 2
    assert len(certified.semantic_sha256) == 64

    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureDecisionContext()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureTargetDecision()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureTargetReplayResult()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureTargetParityReceipt()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureTargetRuntimePin()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureVisibilityProof()
    with pytest.raises(TypeError, match="proof-constructed"):
        RollingCloseMeanTargetIncrementalState()


def test_availability_is_exclusive_before_and_inclusive_at_decision_time() -> None:
    replay = _replay(("100", "102", "106"))
    equal = _certify(replay, lag=timedelta(0))
    after = _certify(replay, lag=timedelta(microseconds=1))

    assert [step.status for step in equal.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
        FeatureTargetStepStatus.READY,
    ]
    assert equal.batch_result.steps[1].context is not None
    assert equal.batch_result.steps[1].context.snapshots[0].available_at == (
        replay.batches[1].as_of
    )
    assert [step.status for step in after.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
    ]

    unavailable_snapshot = after.feature_certification.batch_result.steps[1].snapshots[0]
    visibility_proof = FeatureVisibilityProof._from_feature_result(
        after.feature_certification.batch_result,
        after.feature_certification.receipt,
    )
    with pytest.raises(FeatureNotAvailableError, match="not available"):
        FeatureDecisionContext._from_visible_snapshots(
            visibility_proof=visibility_proof,
            sequence=1,
            runtime_pin=after.runtime_pin,
            snapshots=(unavailable_snapshot,),
        )
    equal_visibility_proof = FeatureVisibilityProof._from_feature_result(
        equal.feature_certification.batch_result,
        equal.feature_certification.receipt,
    )
    copied_snapshot = copy(equal.feature_certification.batch_result.steps[1].snapshots[0])
    with pytest.raises(ValueError, match="canonical visible prefix"):
        FeatureDecisionContext._from_visible_snapshots(
            visibility_proof=equal_visibility_proof,
            sequence=1,
            runtime_pin=equal.runtime_pin,
            snapshots=(copied_snapshot,),
        )
    waiting_context = after.batch_result.steps[1].context
    assert waiting_context is not None
    with pytest.raises(FeatureNotAvailableError, match="no parity-certified"):
        waiting_context.snapshot_for("aqt-security-spy")


def test_delayed_pending_snapshot_releases_at_exact_equal_time_only() -> None:
    replay = _replay(("100", "102", "106"))
    equal = _certify(replay, lag=timedelta(minutes=1))
    after = _certify(replay, lag=timedelta(minutes=1, microseconds=1))

    assert [step.status for step in equal.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
    ]
    released = equal.batch_result.decisions[0].context.snapshots[0]
    assert released.available_at == replay.batches[2].as_of
    assert [step.status for step in after.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
    ]


def test_equal_closed_at_batches_never_select_a_future_sequence() -> None:
    shared_closed_at = BASE + timedelta(minutes=2, seconds=5)
    watermarks = tuple(replace(_watermark(index), closed_at=shared_closed_at) for index in range(3))
    replay = _replay(("100", "102", "106"), watermarks=watermarks)

    certified = _certify(replay, lag=timedelta(0))

    assert [step.status for step in certified.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
        FeatureTargetStepStatus.READY,
    ]
    assert certified.batch_result.decisions[0].context.snapshots == (
        certified.feature_certification.batch_result.steps[1].snapshots[0],
    )
    assert certified.batch_result.decisions[1].context.snapshots == (
        certified.feature_certification.batch_result.steps[2].snapshots[0],
    )


def test_gap_clears_released_and_pending_features_and_requires_fresh_window() -> None:
    released = _certify(
        _replay(("100", "102", None, "108", "112")),
        lag=timedelta(0),
    )
    pending = _certify(
        _replay(("100", "102", None, "108", "112", "116", "120")),
        lag=timedelta(seconds=90),
    )

    assert [step.status for step in released.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
        FeatureTargetStepStatus.SKIPPED_RESET,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
    ]
    assert [step.status for step in pending.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.SKIPPED_RESET,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
    ]
    final_snapshot = pending.batch_result.decisions[0].context.snapshots[0]
    assert tuple(
        observation.event.event_id for observation in final_snapshot.source_observations
    ) == (
        "aqt-security-spy-event-3",
        "aqt-security-spy-event-4",
    )


def test_multi_instrument_targets_are_canonical_and_permutation_invariant() -> None:
    instruments = ("aqt-security-qqq", "aqt-security-spy")
    events = (
        _event(0, "200", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(0, "100"),
        _event(1, "196", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(1, "102"),
    )
    watermarks = tuple(_watermark(index, instruments=instruments) for index in range(2))
    expected = None

    for ordering in permutations(events):
        certified = _certify(
            _replay(events=ordering, watermarks=watermarks),
            lag=timedelta(0),
        )
        target = certified.batch_result.targets[0]
        assert tuple(item.instrument_id for item in target.targets) == instruments
        assert tuple(item.quantity for item in target.targets) == (
            Decimal("0"),
            Decimal("10"),
        )
        if expected is None:
            expected = certified
        else:
            assert certified == expected


def test_partial_multi_instrument_gap_clears_all_pending_consumer_state() -> None:
    instruments = ("aqt-security-qqq", "aqt-security-spy")
    events = (
        _event(0, "200", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(0, "100"),
        _event(1, "204", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(1, "102"),
        _event(2, "106"),
        _event(3, "208", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(3, "108"),
        _event(4, "212", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(4, "112"),
        _event(5, "216", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(5, "116"),
        _event(6, "220", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(6, "120"),
    )
    replay = _replay(
        events=events,
        watermarks=tuple(_watermark(index, instruments=instruments) for index in range(7)),
    )

    certified = _certify(replay, lag=timedelta(seconds=90))

    assert [step.status for step in certified.batch_result.steps] == [
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.SKIPPED_RESET,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.WAITING,
        FeatureTargetStepStatus.READY,
    ]
    final_context = certified.batch_result.decisions[0].context
    assert tuple(snapshot.instrument_id for snapshot in final_context.snapshots) == instruments
    assert {
        tuple(observation.event.event_id for observation in snapshot.source_observations)
        for snapshot in final_context.snapshots
    } == {
        ("aqt-security-qqq-event-3", "aqt-security-qqq-event-4"),
        ("aqt-security-spy-event-3", "aqt-security-spy-event-4"),
    }


def test_future_tape_extension_does_not_change_prior_decision_economics() -> None:
    prefix = _certify(_replay(("100", "102", "106", "99")))
    full = _certify(_replay(("100", "102", "106", "99", "1000")))

    assert [target.targets for target in prefix.batch_result.targets] == [
        target.targets for target in full.batch_result.targets[:2]
    ]
    assert [decision.context.source_batch for decision in prefix.batch_result.decisions] == [
        decision.context.source_batch for decision in full.batch_result.decisions[:2]
    ]
    assert [
        tuple(snapshot.source_observations for snapshot in decision.context.snapshots)
        for decision in prefix.batch_result.decisions
    ] == [
        tuple(snapshot.source_observations for snapshot in decision.context.snapshots)
        for decision in full.batch_result.decisions[:2]
    ]


def test_noncanonical_visible_prefix_and_mixed_certifications_fail_closed() -> None:
    replay = _replay(("100", "102", "106", "110"))
    feature = certify_rolling_close_mean_parity(_artifact(replay, lag=timedelta(0)), replay)
    policy = RollingCloseMeanTargetPolicy(long_quantity=Decimal("10"))
    batch = replay_rolling_close_mean_targets_batch(feature, policy)
    incremental = replay_rolling_close_mean_targets_incremental(feature, policy)
    stale_snapshot = batch.feature_result.steps[1].snapshots[0]
    visibility_proof = FeatureVisibilityProof._from_feature_result(
        batch.feature_result,
        batch.feature_receipt,
    )
    with pytest.raises(ValueError, match="canonical visible prefix"):
        FeatureDecisionContext._from_visible_snapshots(
            visibility_proof=visibility_proof,
            sequence=3,
            runtime_pin=batch.runtime_pin,
            snapshots=(stale_snapshot,),
        )

    different_feature = certify_rolling_close_mean_parity(
        _artifact(replay, lag=timedelta(seconds=1)),
        replay,
    )
    different_incremental = replay_rolling_close_mean_targets_incremental(
        different_feature,
        policy,
    )
    with pytest.raises(FeatureTargetParityError, match="diverged"):
        FeatureTargetParityReceipt._from_equal_results(batch, different_incremental)

    assert FeatureTargetParityReceipt._from_equal_results(batch, incremental).target_count == 3


def test_certified_wrapper_rejects_mutated_aggregate_receipt() -> None:
    certified = _certify(_replay(("100", "102", "106")))
    forged_receipt = copy(certified.receipt)
    object.__setattr__(forged_receipt, "target_count", certified.receipt.target_count + 1)

    with pytest.raises(ValueError, match="inconsistent"):
        CertifiedFeatureTargetReplay(
            feature_certification=certified.feature_certification,
            policy=certified.policy,
            runtime_pin=certified.runtime_pin,
            batch_result=certified.batch_result,
            incremental_result=certified.incremental_result,
            receipt=forged_receipt,
        )


def test_incremental_state_authenticates_exact_next_feature_step() -> None:
    replay = _replay(("100", "102", "106"))
    feature = certify_rolling_close_mean_parity(_artifact(replay), replay)
    policy = RollingCloseMeanTargetPolicy(long_quantity=Decimal("10"))
    runtime_pin = FeatureTargetRuntimePin._from_evidence(
        policy,
        feature.artifact,
        feature.receipt,
    )
    result = feature.incremental_result
    visibility_proof = FeatureVisibilityProof._from_feature_result(result, feature.receipt)
    foreign_feature = certify_rolling_close_mean_parity(
        _artifact(replay, lag=timedelta(seconds=31)),
        replay,
    )
    foreign_pin = FeatureTargetRuntimePin._from_evidence(
        policy,
        foreign_feature.artifact,
        foreign_feature.receipt,
    )
    with pytest.raises(ValueError, match="artifact identity"):
        RollingCloseMeanTargetIncrementalState.initial(
            runtime_pin=foreign_pin,
            visibility_proof=visibility_proof,
        )
    with pytest.raises(ValueError, match="immutable tuple"):
        RollingCloseMeanTargetIncrementalState._create(
            runtime_pin_sha256=runtime_pin.semantic_sha256,
            visibility_proof_sha256=visibility_proof.semantic_sha256,
            feature_step_count=len(result.steps),
            visible_snapshots=[],  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="exact snapshots"):
        RollingCloseMeanTargetIncrementalState._create(
            runtime_pin_sha256=runtime_pin.semantic_sha256,
            visibility_proof_sha256=visibility_proof.semantic_sha256,
            feature_step_count=len(result.steps),
            visible_snapshots=(object(),),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="pending cursor"):
        RollingCloseMeanTargetIncrementalState._create(
            runtime_pin_sha256=runtime_pin.semantic_sha256,
            visibility_proof_sha256=visibility_proof.semantic_sha256,
            feature_step_count=len(result.steps),
            next_sequence=1,
            next_pending_sequence=2,
        )
    state = RollingCloseMeanTargetIncrementalState.initial(
        runtime_pin=runtime_pin,
        visibility_proof=visibility_proof,
    )

    with pytest.raises(ValueError, match="exact next"):
        state.advance(
            runtime_pin=runtime_pin,
            visibility_proof=visibility_proof,
            feature_step=result.steps[1],
            policy=policy,
        )
    with pytest.raises(ValueError, match="runtime policy"):
        state.advance(
            runtime_pin=runtime_pin,
            visibility_proof=visibility_proof,
            feature_step=result.steps[0],
            policy=replace(policy, long_quantity=Decimal("11")),
        )
    for step in result.steps:
        state, _ = state.advance(
            runtime_pin=runtime_pin,
            visibility_proof=visibility_proof,
            feature_step=step,
            policy=policy,
        )
    with pytest.raises(ValueError, match="already consumed"):
        state.advance(
            runtime_pin=runtime_pin,
            visibility_proof=visibility_proof,
            feature_step=result.steps[-1],
            policy=policy,
        )


def test_target_converts_to_intent_using_market_price_not_feature_value() -> None:
    certified = _certify(_replay(("100", "102", "106")))
    decision = certified.batch_result.decisions[0]
    batch = decision.context.source_batch
    snapshot = portfolio_snapshot(
        as_of=batch.as_of,
        current_positions={},
        price_events=batch.events,
    )

    intent = target_to_intent_batch(decision.target, snapshot).intents[0]

    assert intent.reference_price == Decimal("106")
    assert intent.reference_price != decision.context.snapshots[0].value
    assert intent.reference_event_sha256 == batch.events[0].semantic_sha256
    assert intent.strategy_configuration_sha256 == certified.runtime_pin.semantic_sha256


def test_close_equal_to_visible_mean_takes_strict_flat_branch() -> None:
    certified = _certify(_replay(("100", "102", "101")))

    decision = certified.batch_result.decisions[0]

    assert decision.context.snapshots[0].value == Decimal("101")
    assert decision.context.source_batch.events[0].close_price == Decimal("101")
    assert decision.target.targets[0].quantity == Decimal("0")


def test_target_identity_is_decimal_context_independent_and_contracts_are_immutable() -> None:
    replay = _replay(("100", "102", "106"))
    with localcontext() as decimal_context:
        decimal_context.prec = 3
        low_precision = _certify(replay, quantity="123456789")
    with localcontext() as decimal_context:
        decimal_context.prec = 40
        high_precision = _certify(replay, quantity="123456789")

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
    with pytest.raises(FrozenInstanceError):
        low_precision.policy.long_quantity = Decimal("1")  # type: ignore[misc]
    with pytest.raises(ValueError, match="positive and whole"):
        RollingCloseMeanTargetPolicy(long_quantity=Decimal("1.5"))
    with pytest.raises(ValueError, match="at most one day"):
        replace(
            low_precision.policy,
            target_lifetime=timedelta(days=1, microseconds=1),
        )
