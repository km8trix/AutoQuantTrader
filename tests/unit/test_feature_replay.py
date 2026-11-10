from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.domain.feature import (
    EMPTY_FITTED_STATE_SHA256,
    NO_TRAINING_WINDOW_SHA256,
    AuthenticatedFeatureReplayInput,
    FeatureArtifact,
    FeatureComputationMode,
    FeatureMissingDataPolicy,
    FeatureParityError,
    FeatureParityReceipt,
    FeatureReplayResult,
    FeatureReplayStep,
    FeatureSnapshot,
    FeatureStepStatus,
)
from packages.domain.feature_replay import (
    RollingCloseMeanIncrementalState,
    certify_rolling_close_mean_parity,
    create_rolling_close_mean_artifact,
    replay_rolling_close_mean_batch,
    replay_rolling_close_mean_incremental,
)
from packages.domain.market_batch import MarketWatermark, ReplayRevisionPolicy
from packages.domain.models import MarketEvent
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
    revision: int = 1,
    event_id: str | None = None,
    observation_id: str | None = None,
    supersedes: str | None = None,
    available_offset: int = 1,
) -> MarketEvent:
    event_time = BASE + timedelta(minutes=index)
    return MarketEvent(
        event_id=event_id or f"{instrument_id}-event-{index}-r{revision}",
        instrument_id=instrument_id,
        symbol=symbol,
        event_time=event_time,
        available_at=event_time + timedelta(seconds=available_offset),
        close_price=Decimal(price),
        source="phase3-fixture",
        source_sequence=index * 10 + revision,
        observation_id=observation_id,
        revision=revision,
        supersedes_event_revision_id=supersedes,
    )


def _watermark(
    index: int,
    *,
    instruments: tuple[str, ...] = ("aqt-security-spy",),
    revision_policy: ReplayRevisionPolicy = ReplayRevisionPolicy.REVISED_AS_OF,
) -> MarketWatermark:
    event_time = BASE + timedelta(minutes=index)
    return MarketWatermark(
        watermark_id=f"phase3-watermark-{index}-{revision_policy.value}",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=5),
        expected_instrument_ids=instruments,
        revision_policy=revision_policy,
    )


def _replay(
    prices: tuple[str | None, ...] = ("100", "102", "106", "110"),
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
    policy = replay.batches[0].watermark.revision_policy
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
        source_id="phase3-fixture",
        source_kind="synthetic_fixture",
        schema_version="raw-bar-v1",
        price_basis="raw",
        revision_policy=policy,
        calendar_version="phase3-calendar-v1",
        calendar_sha256="6" * 64,
        calendar_hash_version="input-v1",
        tzdata_version="2026a",
        universe_version="phase3-universe-v1",
        universe_sha256="7" * 64,
        universe_hash_version="input-v1",
        corporate_action_version="phase3-actions-v1",
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
        revision_policy=policy,
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
            tape_adapter_version="phase3-unit-tape-v1",
            watermark_policy_version="phase3-unit-watermark-v1",
        ),
        runtime=RuntimePin(
            source_revision="c" * 40,
            dirty_patch_sha256="d" * 64,
            dependency_lock_sha256="e" * 64,
            schema_revision="phase3-unit",
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


def test_reference_definition_and_artifact_are_bounded_content_addressed_facts() -> None:
    replay = _replay()
    artifact = _artifact(replay)

    assert artifact.definition.feature_name == "rolling_close_mean"
    assert artifact.definition.feature_version == "1.0.0"
    assert artifact.definition.lookback_observations == 2
    assert artifact.definition.input_field == "close_price"
    assert artifact.definition.missing_data_policy is FeatureMissingDataPolicy.SKIP_AND_RESET
    assert artifact.training_window_sha256 == NO_TRAINING_WINDOW_SHA256
    assert artifact.fitted_state_sha256 == EMPTY_FITTED_STATE_SHA256
    assert artifact.artifact_id == artifact.semantic_sha256
    assert len(artifact.semantic_sha256) == 64
    assert artifact.lineage.manifest_id == MANIFEST_SHA256
    assert artifact.lineage.manifest_id == artifact.lineage.manifest_sha256
    assert artifact.lineage.replay_run_id == artifact.lineage.replay_run_manifest_sha256
    artifact.lineage.require_replay(replay)

    with pytest.raises(FrozenInstanceError):
        artifact.training_window_sha256 = "5" * 64  # type: ignore[misc]
    with pytest.raises(ValueError, match="no fitted training window"):
        replace(artifact, training_window_sha256="5" * 64)
    with pytest.raises(ValueError, match="immutable empty fitted state"):
        replace(artifact, fitted_state_sha256="5" * 64)
    with pytest.raises(ValueError, match="supports only rolling_close_mean"):
        replace(artifact.definition, feature_name="future_feature")
    with pytest.raises(ValueError, match="lookback=2"):
        replace(artifact.definition, lookback_observations=3)
    with pytest.raises(ValueError, match="non-negative"):
        replace(artifact.definition, publication_lag=timedelta(microseconds=-1))


def test_batch_and_incremental_paths_certify_exact_snapshot_parity() -> None:
    replay = _replay()
    artifact = _artifact(replay)

    certified = certify_rolling_close_mean_parity(artifact, replay)

    assert certified.batch_result.mode is FeatureComputationMode.BATCH
    assert certified.incremental_result.mode is FeatureComputationMode.INCREMENTAL
    assert certified.batch_result.steps == certified.incremental_result.steps
    assert certified.batch_result.transcript_sha256 == (
        certified.incremental_result.transcript_sha256
    )
    assert certified.batch_result.semantic_sha256 != (certified.incremental_result.semantic_sha256)
    assert [step.status for step in certified.batch_result.steps] == [
        FeatureStepStatus.WARMING,
        FeatureStepStatus.READY,
        FeatureStepStatus.READY,
        FeatureStepStatus.READY,
    ]
    assert [snapshot.value for snapshot in certified.batch_result.snapshots] == [
        Decimal("101"),
        Decimal("104"),
        Decimal("108"),
    ]
    assert [
        tuple(observation.event.event_id for observation in snapshot.source_observations)
        for snapshot in certified.batch_result.snapshots
    ] == [
        ("aqt-security-spy-event-0-r1", "aqt-security-spy-event-1-r1"),
        ("aqt-security-spy-event-1-r1", "aqt-security-spy-event-2-r1"),
        ("aqt-security-spy-event-2-r1", "aqt-security-spy-event-3-r1"),
    ]
    assert certified.receipt.snapshot_count == 3
    assert certified.receipt.snapshot_ids == tuple(
        snapshot.snapshot_id for snapshot in certified.batch_result.snapshots
    )
    assert len(certified.semantic_sha256) == 64
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureSnapshot()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureReplayResult()
    with pytest.raises(TypeError, match="proof-constructed"):
        FeatureParityReceipt()
    with pytest.raises(TypeError, match="proof-constructed"):
        AuthenticatedFeatureReplayInput()
    with pytest.raises(TypeError, match="proof-constructed"):
        RollingCloseMeanIncrementalState()


def test_publication_lag_is_part_of_identity_and_advances_availability() -> None:
    replay = _replay(("100", "102"))
    artifact = _artifact(replay, lag=timedelta(minutes=2))
    no_lag_artifact = _artifact(replay, lag=timedelta(0))

    snapshot = certify_rolling_close_mean_parity(artifact, replay).batch_result.snapshots[0]
    no_lag_snapshot = certify_rolling_close_mean_parity(
        no_lag_artifact,
        replay,
    ).batch_result.snapshots[0]

    assert snapshot.observation_time == BASE + timedelta(minutes=1)
    assert snapshot.available_at == replay.batches[1].as_of + timedelta(minutes=2)
    assert no_lag_snapshot.available_at == replay.batches[1].as_of
    assert artifact.semantic_sha256 != no_lag_artifact.semantic_sha256
    assert snapshot.semantic_sha256 != no_lag_snapshot.semantic_sha256


def test_incomplete_batch_emits_reset_and_windows_never_bridge_the_gap() -> None:
    replay = _replay(("100", "102", None, "108", "112"))
    artifact = _artifact(replay)

    certified = certify_rolling_close_mean_parity(artifact, replay)
    steps = certified.batch_result.steps

    assert [step.status for step in steps] == [
        FeatureStepStatus.WARMING,
        FeatureStepStatus.READY,
        FeatureStepStatus.SKIPPED_RESET,
        FeatureStepStatus.WARMING,
        FeatureStepStatus.READY,
    ]
    assert steps[2].reset_instrument_ids == ("aqt-security-spy",)
    assert [snapshot.value for snapshot in certified.batch_result.snapshots] == [
        Decimal("101"),
        Decimal("110"),
    ]
    assert tuple(
        observation.event.event_id
        for observation in certified.batch_result.snapshots[-1].source_observations
    ) == (
        "aqt-security-spy-event-3-r1",
        "aqt-security-spy-event-4-r1",
    )


def test_multi_instrument_outputs_are_canonical_and_input_permutation_invariant() -> None:
    instruments = ("aqt-security-qqq", "aqt-security-spy")
    events = (
        _event(0, "200", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(0, "100"),
        _event(1, "204", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(1, "102"),
    )
    watermarks = tuple(_watermark(index, instruments=instruments) for index in range(2))
    expected: tuple[ReplayResult, FeatureArtifact, object] | None = None

    for ordering in permutations(events):
        replay = _replay(events=ordering, watermarks=watermarks)
        artifact = _artifact(replay)
        certified = certify_rolling_close_mean_parity(artifact, replay)
        assert [snapshot.instrument_id for snapshot in certified.batch_result.snapshots] == [
            "aqt-security-qqq",
            "aqt-security-spy",
        ]
        assert [snapshot.value for snapshot in certified.batch_result.snapshots] == [
            Decimal("202"),
            Decimal("101"),
        ]
        current = (replay, artifact, certified)
        if expected is None:
            expected = current
        else:
            assert current == expected


def test_replay_revision_policy_controls_exact_selected_input() -> None:
    initial = _event(
        1,
        "102",
        event_id="spy-observation-1-r1",
        observation_id="spy-observation-1",
    )
    correction = _event(
        1,
        "106",
        revision=2,
        event_id="spy-observation-1-r2",
        observation_id="spy-observation-1",
        supersedes=initial.event_id,
        available_offset=2,
    )
    events = (_event(0, "100"), initial, correction)
    revised_replay = _replay(
        events=events,
        watermarks=(_watermark(0), _watermark(1)),
    )
    first_seen_replay = _replay(
        events=events,
        watermarks=(
            _watermark(0, revision_policy=ReplayRevisionPolicy.FIRST_SEEN),
            _watermark(1, revision_policy=ReplayRevisionPolicy.FIRST_SEEN),
        ),
    )

    revised = certify_rolling_close_mean_parity(
        _artifact(revised_replay),
        revised_replay,
    ).batch_result.snapshots[0]
    first_seen = certify_rolling_close_mean_parity(
        _artifact(first_seen_replay),
        first_seen_replay,
    ).batch_result.snapshots[0]

    assert revised.value == Decimal("103")
    assert revised.source_observations[-1].event == correction
    assert first_seen.value == Decimal("101")
    assert first_seen.source_observations[-1].event == initial


def test_feature_output_prefix_does_not_use_future_batches() -> None:
    prefix_replay = _replay(("100", "102", "106"))
    full_replay = _replay(("100", "102", "106", "1000"))
    prefix = certify_rolling_close_mean_parity(
        _artifact(prefix_replay),
        prefix_replay,
    ).batch_result.snapshots
    full = certify_rolling_close_mean_parity(
        _artifact(full_replay),
        full_replay,
    ).batch_result.snapshots

    assert len(prefix) == 2
    assert [snapshot.value for snapshot in prefix] == [snapshot.value for snapshot in full[:2]]
    assert [snapshot.source_observations for snapshot in prefix] == [
        snapshot.source_observations for snapshot in full[:2]
    ]
    assert [snapshot.available_at for snapshot in prefix] == [
        snapshot.available_at for snapshot in full[:2]
    ]


def test_lineage_changes_and_nonsequential_incremental_inputs_fail_closed() -> None:
    replay = _replay(("100", "102", "106"))
    artifact = _artifact(replay)
    changed = replace(replay, tape_sha256="f" * 64)

    with pytest.raises(ValueError, match="exact immutable lineage"):
        replay_rolling_close_mean_batch(artifact, changed)
    with pytest.raises(ValueError, match="exact immutable lineage"):
        replay_rolling_close_mean_incremental(artifact, changed)

    state = RollingCloseMeanIncrementalState.initial(artifact)
    with pytest.raises(ValueError, match="exact next lineage batch"):
        state.advance(artifact, replay.batches[1])
    state, _ = state.advance(artifact, replay.batches[0])
    with pytest.raises(ValueError, match="exact next lineage batch"):
        state.advance(artifact, replay.batches[0])
    state, _ = state.advance(artifact, replay.batches[1])
    state, _ = state.advance(artifact, replay.batches[2])
    with pytest.raises(ValueError, match="already consumed"):
        state.advance(artifact, replay.batches[2])


def test_noncanonical_transcript_cannot_reach_a_parity_receipt() -> None:
    replay = _replay(("100", "102", "106"))
    artifact = _artifact(replay)
    incremental_result = replay_rolling_close_mean_incremental(artifact, replay)
    divergent_step = FeatureReplayStep(
        sequence=1,
        artifact_sha256=artifact.semantic_sha256,
        source_batch=replay.batches[1],
        status=FeatureStepStatus.WARMING,
        snapshots=(),
    )
    with pytest.raises(ValueError, match="eligible feature windows must emit READY"):
        FeatureReplayResult._from_reducer(
            mode=FeatureComputationMode.INCREMENTAL,
            artifact=artifact,
            source_replay=replay,
            steps=(incremental_result.steps[0], divergent_step, incremental_result.steps[2]),
        )


def test_parity_receipt_rejects_distinct_valid_artifacts() -> None:
    replay = _replay(("100", "102"))
    baseline = replay_rolling_close_mean_batch(_artifact(replay), replay)
    different = replay_rolling_close_mean_incremental(
        _artifact(replay, lag=timedelta(seconds=31)),
        replay,
    )

    with pytest.raises(FeatureParityError, match="diverged"):
        FeatureParityReceipt._from_equal_results(baseline, different)


def test_exact_mean_preserves_values_beyond_sql_transport_scale() -> None:
    replay = _replay(("0.0000000001", "0.0000000002"))

    certified = certify_rolling_close_mean_parity(_artifact(replay), replay)

    assert certified.batch_result.snapshots[0].value == Decimal("0.00000000015")


def test_partial_multi_instrument_gap_resets_every_expected_stream() -> None:
    instruments = ("aqt-security-qqq", "aqt-security-spy")
    events = (
        _event(0, "200", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(0, "100"),
        _event(1, "102"),
        _event(2, "208", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(2, "106"),
        _event(3, "212", instrument_id="aqt-security-qqq", symbol="QQQ"),
        _event(3, "110"),
    )
    watermarks = tuple(_watermark(index, instruments=instruments) for index in range(4))
    replay = _replay(events=events, watermarks=watermarks)

    certified = certify_rolling_close_mean_parity(_artifact(replay), replay)

    assert [step.status for step in certified.batch_result.steps] == [
        FeatureStepStatus.WARMING,
        FeatureStepStatus.SKIPPED_RESET,
        FeatureStepStatus.WARMING,
        FeatureStepStatus.READY,
    ]
    assert certified.batch_result.steps[1].reset_instrument_ids == instruments
    assert [snapshot.value for snapshot in certified.batch_result.snapshots] == [
        Decimal("210"),
        Decimal("108"),
    ]


def test_feature_identity_ignores_ambient_decimal_context() -> None:
    replay = _replay(("100.00", "102.00", "106.00"))
    artifact = _artifact(replay)
    with localcontext() as decimal_context:
        decimal_context.prec = 3
        low_precision = certify_rolling_close_mean_parity(artifact, replay)
    with localcontext() as decimal_context:
        decimal_context.prec = 40
        high_precision = certify_rolling_close_mean_parity(artifact, replay)

    assert low_precision == high_precision
    assert low_precision.semantic_sha256 == high_precision.semantic_sha256
