from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from enum import StrEnum

import pytest

from packages.domain.market_batch import (
    LateEventPolicy,
    MarketWatermark,
    MissingDataPolicy,
    ReplayRevisionPolicy,
)
from packages.domain.models import MarketEvent
from packages.domain.replay import ReplayResult, replay_market_events
from packages.domain.replay_manifest import (
    NOT_APPLICABLE,
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayManifestDecodeError,
    ReplayPlanPin,
    ReplayRunManifest,
    RuntimePin,
)

EVENT_TIME = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
CLOSED_AT = EVENT_TIME + timedelta(seconds=5)


class TextLike(StrEnum):
    RAW = "raw"


def replay_result() -> ReplayResult:
    event = MarketEvent(
        event_id="fixture-event-r1",
        instrument_id="US-ETF-SPY",
        symbol="SPY",
        event_time=EVENT_TIME,
        available_at=CLOSED_AT,
        close_price=Decimal("100.00"),
        source="recorded-fixture",
        source_sequence=1,
        observation_id="fixture-observation",
        revision=1,
    )
    watermark = MarketWatermark(
        watermark_id="fixture-watermark",
        event_time_through=EVENT_TIME,
        closed_at=CLOSED_AT,
        expected_instrument_ids=("US-ETF-SPY",),
    )
    return replay_market_events(events=(event,), watermarks=(watermark,))


def dataset_pin() -> DatasetPin:
    return DatasetPin(
        manifest_id="a" * 64,
        manifest_sha256="a" * 64,
        source_tape_sha256="6" * 64,
        source_id="recorded-fixture",
        source_kind="recorded_fixture",
        schema_version="raw-bar-v1",
        price_basis="raw",
        revision_policy=ReplayRevisionPolicy.REVISED_AS_OF,
        calendar_version="xnys-fixture-v1",
        calendar_sha256="b" * 64,
        calendar_hash_version="input-v1",
        tzdata_version="2026a",
        universe_version="etf-fixture-v1",
        universe_sha256="c" * 64,
        universe_hash_version="input-v1",
        corporate_action_version="actions-fixture-v1",
        corporate_action_sha256="d" * 64,
        corporate_action_hash_version="input-v1",
        row_count=1,
        partitions=(
            DatasetPartitionPin(
                ordinal=0,
                partition_id="e" * 64,
                object_id="f" * 64,
                object_key=f"normalized/sha256/ff/{'f' * 64}.parquet",
                format="parquet",
                byte_sha256="f" * 64,
                semantic_sha256="1" * 64,
                semantic_checksum_version="input-v1",
                size_bytes=1024,
                row_count=1,
                event_time_start=EVENT_TIME,
                event_time_end=EVENT_TIME,
                available_at_start=CLOSED_AT,
                available_at_end=CLOSED_AT,
            ),
        ),
    )


def replay_plan() -> ReplayPlanPin:
    return ReplayPlanPin(
        coverage_start=EVENT_TIME,
        coverage_end=EVENT_TIME,
        interval="1m",
        decision_lag=timedelta(seconds=5, microseconds=123),
        revision_policy=ReplayRevisionPolicy.REVISED_AS_OF,
        missing_data_policy=MissingDataPolicy.SKIP,
        late_event_policy=LateEventPolicy.HALT,
        expected_instrument_ids=("US-ETF-SPY",),
        watermark_count=1,
        watermarks_sha256="2" * 64,
    )


def runtime_pin() -> RuntimePin:
    return RuntimePin(
        source_revision="3" * 40,
        dirty_patch_sha256="4" * 64,
        dependency_lock_sha256="5" * 64,
        schema_revision="0006_replay_run_manifests",
        python_version="3.12.10",
        pyarrow_version="21.0.0",
    )


def replay_manifest() -> ReplayRunManifest:
    return ReplayRunManifest.from_replay_result(
        dataset=dataset_pin(),
        plan=replay_plan(),
        engine=EnginePin(
            tape_adapter_version="manifest-raw-bar-tape-v1",
            watermark_policy_version="decision-lag-watermark-v1",
        ),
        runtime=runtime_pin(),
        result=replay_result(),
        source_tape_sha256="6" * 64,
    )


def test_manifest_factory_is_deterministic_sealed_and_round_trips() -> None:
    first = replay_manifest()
    second = replay_manifest()

    assert first == second
    assert first.run_id == first.manifest_sha256
    assert first.idempotency_key == first.input_sha256
    assert len(first.input_sha256) == 64
    assert len(first.manifest_sha256) == 64
    assert first.runtime.strategy_version == NOT_APPLICABLE
    assert first.runtime.cost_model_version == NOT_APPLICABLE
    assert first.runtime.fill_model_version == NOT_APPLICABLE
    assert first.runtime.benchmark_version == NOT_APPLICABLE
    assert first.runtime.rng_algorithm == NOT_APPLICABLE
    assert first.runtime.rng_seed is None
    assert NOT_APPLICABLE in first.canonical_json
    assert (
        ReplayRunManifest.from_canonical_json(
            first.canonical_json,
            expected_run_id=first.run_id,
            expected_manifest_sha256=first.manifest_sha256,
        )
        == first
    )
    with pytest.raises(FrozenInstanceError):
        first.run_id = "forged"  # type: ignore[misc]


def test_input_identity_excludes_output_but_run_identity_includes_it() -> None:
    baseline = replay_manifest()
    different_output = replace(baseline, replay_semantic_sha256="6" * 64)
    different_engine = replace(
        baseline,
        engine=replace(baseline.engine, tape_adapter_version="manifest-raw-bar-tape-v2"),
    )
    different_source_tape = replace(
        baseline,
        dataset=replace(baseline.dataset, source_tape_sha256="7" * 64),
    )

    assert different_output.input_sha256 == baseline.input_sha256
    assert different_output.manifest_sha256 != baseline.manifest_sha256
    assert different_output.run_id != baseline.run_id
    assert different_engine.input_sha256 != baseline.input_sha256
    assert different_engine.manifest_sha256 != baseline.manifest_sha256
    assert different_source_tape.input_sha256 != baseline.input_sha256
    assert different_source_tape.run_id != baseline.run_id


def test_manifest_identity_ignores_ambient_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 3
        low_precision = replay_manifest()
    with localcontext() as context:
        context.prec = 40
        high_precision = replay_manifest()

    assert low_precision == high_precision
    assert low_precision.canonical_json == high_precision.canonical_json


def test_factory_rejects_inconsistent_replay_result_evidence() -> None:
    result = replay_result()

    with pytest.raises(ValueError, match="complete batch evidence"):
        ReplayRunManifest.from_replay_result(
            dataset=dataset_pin(),
            plan=replay_plan(),
            engine=EnginePin("tape-v1", "watermark-v1"),
            runtime=runtime_pin(),
            result=replace(result, complete_batch_ids=()),
            source_tape_sha256="6" * 64,
        )
    with pytest.raises(ValueError, match="batch event evidence"):
        ReplayRunManifest.from_replay_result(
            dataset=dataset_pin(),
            plan=replay_plan(),
            engine=EnginePin("tape-v1", "watermark-v1"),
            runtime=runtime_pin(),
            result=replace(result, processed_event_ids=()),
            source_tape_sha256="6" * 64,
        )
    with pytest.raises(ValueError, match="immutable dataset pin"):
        ReplayRunManifest.from_replay_result(
            dataset=dataset_pin(),
            plan=replay_plan(),
            engine=EnginePin("tape-v1", "watermark-v1"),
            runtime=runtime_pin(),
            result=result,
            source_tape_sha256="7" * 64,
        )


def test_dataset_pin_requires_exact_content_addressed_ordered_facts() -> None:
    partition = dataset_pin().partitions[0]

    with pytest.raises(ValueError, match="object_id must equal"):
        replace(partition, object_id="7" * 64)
    with pytest.raises(ValueError, match="canonical normalized content address"):
        replace(partition, object_key="normalized/forged.parquet")
    with pytest.raises(ValueError, match="format must be parquet"):
        replace(partition, format="csv")
    with pytest.raises(ValueError, match="size_bytes"):
        replace(partition, size_bytes=0)
    with pytest.raises(ValueError, match="semantic_checksum_version"):
        replace(partition, semantic_checksum_version="implicit")
    with pytest.raises(ValueError, match="event-time range"):
        replace(partition, event_time_start=EVENT_TIME + timedelta(microseconds=1))
    with pytest.raises(ValueError, match="availability range"):
        replace(partition, available_at_start=CLOSED_AT + timedelta(microseconds=1))
    with pytest.raises(ValueError, match="contiguous and ordered"):
        replace(dataset_pin(), partitions=(replace(partition, ordinal=1),))
    with pytest.raises(ValueError, match="ordered partition total"):
        replace(dataset_pin(), row_count=2)
    with pytest.raises(ValueError, match="repository-owned fixture"):
        replace(dataset_pin(), source_kind="vendor")
    with pytest.raises(ValueError, match="raw prices"):
        replace(dataset_pin(), price_basis="adjusted")
    with pytest.raises(ValueError, match="raw prices"):
        replace(dataset_pin(), price_basis=TextLike.RAW)
    with pytest.raises(ValueError, match="manifest_id must equal"):
        replace(dataset_pin(), manifest_sha256="8" * 64)
    with pytest.raises(ValueError, match="checksum versions must match"):
        replace(
            dataset_pin(),
            partitions=(replace(partition, semantic_checksum_version="arrow-v2"),),
        )
    with pytest.raises(ValueError, match="reference hash versions must match"):
        replace(dataset_pin(), calendar_hash_version="persisted-v2")


def test_plan_is_exact_utc_sorted_and_policy_bound() -> None:
    with pytest.raises(ValueError, match="coverage_end"):
        replace(replay_plan(), coverage_end=EVENT_TIME - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="decision_lag"):
        replace(replay_plan(), decision_lag=-timedelta(microseconds=1))
    with pytest.raises(ValueError, match="unique and sorted"):
        replace(
            replay_plan(),
            expected_instrument_ids=("US-ETF-SPY", "US-ETF-QQQ"),
        )
    with pytest.raises(ValueError, match="revision policy must match"):
        replace(
            replay_manifest(),
            plan=replace(
                replay_plan(),
                revision_policy=ReplayRevisionPolicy.FIRST_SEEN,
            ),
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(replay_plan(), coverage_start=EVENT_TIME.replace(tzinfo=None))


def test_runtime_pin_is_explicit_and_cannot_carry_research_scope() -> None:
    assert runtime_pin().semantic_sha256 == runtime_pin().semantic_sha256

    with pytest.raises(ValueError, match="source_revision"):
        replace(runtime_pin(), source_revision="main")
    with pytest.raises(ValueError, match="strategy_version"):
        replace(runtime_pin(), strategy_version="momentum-v1")
    with pytest.raises(ValueError, match="rng_seed"):
        RuntimePin(
            source_revision="3" * 40,
            dirty_patch_sha256="4" * 64,
            dependency_lock_sha256="5" * 64,
            schema_revision="0006_replay_run_manifests",
            python_version="3.12.10",
            pyarrow_version="21.0.0",
            rng_seed=1,  # type: ignore[arg-type]
        )


def test_result_counts_are_complete_and_match_pinned_watermarks() -> None:
    manifest = replay_manifest()

    with pytest.raises(ValueError, match="cover every batch"):
        replace(manifest, skipped_batch_count=1)
    with pytest.raises(ValueError, match="watermark_count"):
        replace(manifest, batch_count=2, complete_batch_count=2)
    assert replace(manifest, processed_event_count=0).processed_event_count == 0
    with pytest.raises(ValueError, match="processed_event_count"):
        replace(manifest, processed_event_count=-1)


def test_strict_decoder_rejects_tampering_and_noncanonical_bytes() -> None:
    manifest = replay_manifest()
    forged_input = manifest.canonical_json.replace(manifest.input_sha256, "9" * 64, 1)
    forged_outcome = manifest.canonical_json.replace(
        '"value":"completed"',
        '"value":"failed"',
        1,
    )
    duplicate_json_key = manifest.canonical_json.replace(
        '{"type":"mapping"',
        '{"type":"mapping","type":"mapping"',
        1,
    )

    with pytest.raises(ReplayManifestDecodeError, match="input digest"):
        ReplayRunManifest.from_canonical_json(forged_input)
    with pytest.raises(ReplayManifestDecodeError, match="outcome"):
        ReplayRunManifest.from_canonical_json(forged_outcome)
    with pytest.raises(ReplayManifestDecodeError, match="duplicate JSON key"):
        ReplayRunManifest.from_canonical_json(duplicate_json_key)
    with pytest.raises(ReplayManifestDecodeError, match="not canonical"):
        ReplayRunManifest.from_canonical_json(f"{manifest.canonical_json} ")
    with pytest.raises(ReplayManifestDecodeError, match="run identity"):
        ReplayRunManifest.from_canonical_json(
            manifest.canonical_json,
            expected_run_id="0" * 64,
        )


def test_strict_decoder_preserves_exact_microsecond_decision_lag() -> None:
    manifest = replay_manifest()

    restored = ReplayRunManifest.from_canonical_json(manifest.canonical_json)

    assert restored.plan.decision_lag == timedelta(seconds=5, microseconds=123)
    assert restored.plan.coverage_start == EVENT_TIME
    assert restored.plan.coverage_end == EVENT_TIME


def test_strict_decoder_bounds_canonical_node_depth() -> None:
    node = '{"type":"tuple","value":[]}'
    for _ in range(66):
        node = f'{{"type":"tuple","value":[{node}]}}'

    with pytest.raises(ReplayManifestDecodeError, match="nesting is too deep"):
        ReplayRunManifest.from_canonical_json(node)
