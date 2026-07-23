from __future__ import annotations

from copy import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pyarrow as pa
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from packages.application.manifest_replay import execute_and_seal_manifest_replay
from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.datasets import (
    DatasetDecodeError,
    LocalParquetObjectStore,
    ManifestBarReader,
    ManifestReplayTape,
    ManifestReplayTapeReader,
    ReplayTapePlan,
    certify_manifest_rolling_close_mean,
    certify_manifest_rolling_close_mean_targets,
    market_event_from_raw_bar,
    replay_manifest_tape,
    validate_manifest_watermark_policy,
)
from packages.domain.feature_target import RollingCloseMeanTargetPolicy
from packages.domain.market_batch import MarketBatchStatus, ReplayRevisionPolicy
from packages.domain.replay import LateMarketEvent
from packages.domain.replay_manifest import ReplayRunManifest, RuntimePin
from packages.market_data import BarInterval
from packages.persistence.database import create_database_engine
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.schema import (
    calendar_sessions,
    corporate_action_revisions,
    corporate_action_set_members,
    dataset_manifests,
    dataset_partitions,
    market_data_entitlements,
    market_data_sources,
    universe_memberships,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "market_data" / "phase1_bars.jsonl"
START = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
END = datetime(2026, 7, 15, 13, 34, tzinfo=UTC)


class AcceptingReplayManifestPublisher:
    def publish(self, manifest: ReplayRunManifest, tape: ManifestReplayTape) -> bool:
        return True


def phase3_runtime_pin() -> RuntimePin:
    return RuntimePin(
        source_revision="1" * 40,
        dirty_patch_sha256="2" * 64,
        dependency_lock_sha256="3" * 64,
        schema_revision="phase3-feature-test",
        python_version="3.12",
        pyarrow_version=pa.__version__,
    )


def migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/manifest-replay.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def published_reader(
    tmp_path: Path,
) -> tuple[Engine, str, ManifestReplayTapeReader, ManifestBarReader]:
    engine = migrated_engine(tmp_path)
    lake = tmp_path / "lake"
    outcome = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )
    assert outcome.manifest_id is not None
    catalog = SqlMarketDataCatalog(engine)
    object_store = LocalParquetObjectStore(lake)
    return (
        engine,
        outcome.manifest_id,
        ManifestReplayTapeReader(catalog=catalog, object_store=object_store),
        ManifestBarReader(catalog=catalog, object_store=object_store),
    )


def test_plan_uses_pinned_references_and_tape_keeps_every_revision(tmp_path: Path) -> None:
    _, manifest_id, reader, snapshot_reader = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )

    assert tuple(watermark.event_time_through for watermark in plan.watermarks) == tuple(
        START + timedelta(minutes=offset) for offset in range(4)
    )
    assert all(
        watermark.expected_instrument_ids == ("aqt-security-spy",) for watermark in plan.watermarks
    )
    assert all(
        watermark.revision_policy is ReplayRevisionPolicy.REVISED_AS_OF
        for watermark in plan.watermarks
    )

    tape = reader.read(plan)
    assert tape.calendar_tzdata_version == "system-zoneinfo-2026a-fixture"
    assert len(tape.bars) == len(tape.events) == 4
    first_revision, correction = sorted(
        (bar for bar in tape.bars if bar.event_time == START),
        key=lambda bar: bar.revision,
    )
    assert (first_revision.revision, correction.revision) == (1, 2)
    assert correction.supersedes_event_revision_id == first_revision.event_revision_id
    mapped = market_event_from_raw_bar(correction)
    assert mapped == next(event for event in tape.events if event.revision == 2)
    assert mapped.event_id == correction.event_revision_id
    assert mapped.observation_id == correction.observation_id
    assert mapped.event_time == correction.event_time
    assert mapped.available_at == correction.available_at
    assert mapped.source_sequence == correction.source_sequence
    assert mapped.event_time != correction.vendor_published_at
    assert mapped.available_at != correction.ingested_at
    assert (
        market_event_from_raw_bar(replace(first_revision, source_sequence=None)).source_sequence
        is None
    )
    assert (
        market_event_from_raw_bar(replace(first_revision, source_sequence=0)).source_sequence == 0
    )

    snapshot = snapshot_reader.bars_as_of(
        manifest_id=manifest_id,
        as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
    )
    assert len(snapshot) == 1
    assert snapshot[0].revision == 2
    assert len(tape.bars) > len(snapshot)


def test_replay_includes_calendar_slice_with_quarantined_bar_as_incomplete(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    tape = reader.read(plan)

    result = replay_manifest_tape(tape)

    assert len(result.batches) == 4
    assert [batch.status for batch in result.batches] == [
        MarketBatchStatus.COMPLETE,
        MarketBatchStatus.COMPLETE,
        MarketBatchStatus.COMPLETE,
        MarketBatchStatus.INCOMPLETE,
    ]
    assert result.batches[-1].watermark.event_time_through == END
    assert result.batches[-1].missing_instrument_ids == ("aqt-security-spy",)
    assert result.skipped_batch_ids == (result.batches[-1].batch_id,)
    assert result.batches[0].events[0].revision == 2


def test_manifest_tape_certifies_exact_feature_batch_incremental_parity(
    tmp_path: Path,
) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    tape = reader.read(plan)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=phase3_runtime_pin(),
        repository=AcceptingReplayManifestPublisher(),
    )

    certified = certify_manifest_rolling_close_mean(
        tape,
        replay_run_manifest=sealed.manifest,
        implementation_sha256="f" * 64,
        publication_lag=timedelta(seconds=30),
    )
    repeated = certify_manifest_rolling_close_mean(
        tape,
        replay_run_manifest=sealed.manifest,
        implementation_sha256="f" * 64,
        publication_lag=timedelta(seconds=30),
    )

    assert certified == repeated
    assert certified.artifact.lineage.manifest_id == tape.manifest_id
    assert certified.artifact.lineage.manifest_sha256 == tape.manifest_hash
    assert certified.artifact.lineage.manifest_tape_sha256 == tape.semantic_sha256
    assert certified.artifact.lineage.replay_run_id == sealed.manifest.run_id
    assert certified.artifact.lineage.replay_run_manifest_sha256 == (
        sealed.manifest.manifest_sha256
    )
    assert certified.artifact.lineage.replay_plan_sha256 == sealed.manifest.plan.semantic_sha256
    assert certified.batch_result.steps == certified.incremental_result.steps
    assert [step.status.value for step in certified.batch_result.steps] == [
        "warming",
        "ready",
        "ready",
        "skipped_reset",
    ]
    assert certified.receipt.snapshot_count == 2
    assert certified.batch_result.snapshots[0].source_observations[0].event.revision == 2

    target_certified = certify_manifest_rolling_close_mean_targets(
        tape,
        replay_run_manifest=sealed.manifest,
        implementation_sha256="f" * 64,
        publication_lag=timedelta(seconds=30),
        target_policy=RollingCloseMeanTargetPolicy(long_quantity=Decimal("10")),
    )
    assert target_certified.feature_certification == certified
    assert target_certified.batch_result.steps == target_certified.incremental_result.steps
    assert [step.status.value for step in target_certified.batch_result.steps] == [
        "waiting",
        "waiting",
        "ready",
        "skipped_reset",
    ]
    assert target_certified.receipt.target_count == 1
    assert target_certified.batch_result.targets[0].strategy_configuration_sha256 == (
        target_certified.runtime_pin.semantic_sha256
    )

    forged_manifest = replace(sealed.manifest, replay_semantic_sha256="0" * 64)
    with pytest.raises(ValueError, match="does not authenticate"):
        certify_manifest_rolling_close_mean(
            tape,
            replay_run_manifest=forged_manifest,
            implementation_sha256="f" * 64,
            publication_lag=timedelta(seconds=30),
        )
    with pytest.raises(ValueError, match="does not authenticate"):
        certify_manifest_rolling_close_mean_targets(
            tape,
            replay_run_manifest=forged_manifest,
            implementation_sha256="f" * 64,
            publication_lag=timedelta(seconds=30),
            target_policy=RollingCloseMeanTargetPolicy(long_quantity=Decimal("10")),
        )


def test_five_second_decision_lag_exposes_correction_as_late(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(seconds=5),
    )
    tape = reader.read(plan)

    with pytest.raises(LateMarketEvent, match="after its watermark"):
        replay_manifest_tape(tape)


def test_manifest_policy_cannot_be_overridden_by_external_watermarks(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    overridden = (
        replace(plan.watermarks[0], revision_policy=ReplayRevisionPolicy.FIRST_SEEN),
        *plan.watermarks[1:],
    )

    with pytest.raises(ValueError, match="exactly match"):
        validate_manifest_watermark_policy(plan, overridden)


def test_catalog_recomputes_manifest_content_pin(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(dataset_manifests)
            .where(dataset_manifests.c.manifest_id == manifest_id)
            .values(manifest_hash="f" * 64)
        )

    with pytest.raises(ImmutableFactConflict, match="content pins"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_vendor_manifest_is_not_authorized_by_fixture_replay_adapter(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        source_id = connection.scalar(
            sa.select(dataset_manifests.c.source_id).where(
                dataset_manifests.c.manifest_id == manifest_id
            )
        )
        connection.execute(
            sa.update(market_data_sources)
            .where(market_data_sources.c.source_id == source_id)
            .values(kind="vendor")
        )

    with pytest.raises(DatasetDecodeError, match="fixture sources"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_manifest_row_bound_is_checked_before_object_materialization(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    excessive = 5_000_001
    with engine.begin() as connection:
        connection.execute(
            sa.update(dataset_manifests)
            .where(dataset_manifests.c.manifest_id == manifest_id)
            .values(row_count=excessive)
        )
        connection.execute(sa.update(dataset_partitions).values(row_count=excessive))

    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    with pytest.raises(DatasetDecodeError, match="bounded read"):
        reader.read(plan)


def test_catalog_rejects_calendar_row_tamper_against_content_hash(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(calendar_sessions)
            .where(calendar_sessions.c.session_label == "2026-07-15")
            .values(opens_at=datetime(2026, 7, 15, 13, 30, 1, tzinfo=UTC))
        )

    with pytest.raises(ImmutableFactConflict, match="reference rows"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_catalog_rejects_universe_row_tamper_against_content_hash(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(universe_memberships).values(
                available_at=datetime(2025, 12, 20, 12, 0, 1, tzinfo=UTC)
            )
        )

    with pytest.raises(ImmutableFactConflict, match="reference rows"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_catalog_rejects_corporate_action_fact_tamper(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        action_revision_id, effective_at = connection.execute(
            sa.select(
                corporate_action_revisions.c.action_revision_id,
                corporate_action_revisions.c.effective_at,
            ).order_by(corporate_action_revisions.c.action_revision_id)
        ).first()  # type: ignore[misc]
        connection.execute(
            sa.update(corporate_action_revisions)
            .where(corporate_action_revisions.c.action_revision_id == action_revision_id)
            .values(effective_at=effective_at + timedelta(seconds=1))
        )

    with pytest.raises(ImmutableFactConflict, match="corporate-action fact hash"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_catalog_rejects_noncontiguous_action_set_ordinals(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        connection.execute(
            sa.update(corporate_action_set_members)
            .where(corporate_action_set_members.c.ordinal == 3)
            .values(ordinal=9)
        )

    with pytest.raises(ImmutableFactConflict, match="contiguous corporate-action"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_fixture_replay_rejects_a_licensed_source(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        connection.execute(sa.update(market_data_sources).values(licensed=True))

    with pytest.raises(DatasetDecodeError, match="unlicensed"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_fixture_replay_rejects_mixed_entitlement_statuses(tmp_path: Path) -> None:
    engine, manifest_id, reader, _ = published_reader(tmp_path)
    with engine.begin() as connection:
        source_id = connection.scalar(
            sa.select(dataset_manifests.c.source_id).where(
                dataset_manifests.c.manifest_id == manifest_id
            )
        )
        connection.execute(
            sa.insert(market_data_entitlements).values(
                entitlement_id="unexpected-active-entitlement",
                source_id=source_id,
                status="active",
                scope="negative replay authorization test",
                effective_from=datetime(2026, 1, 1, tzinfo=UTC),
                effective_to=None,
                terms_digest="a" * 64,
                observed_at=datetime(2026, 7, 16, tzinfo=UTC),
            )
        )

    with pytest.raises(DatasetDecodeError, match="exclusively fixture-only"):
        reader.build_plan(
            manifest_id=manifest_id,
            event_time_start=START,
            event_time_end=END,
            interval=BarInterval.ONE_MINUTE,
            decision_lag=timedelta(minutes=1),
        )


def test_reader_rederives_and_rejects_a_forged_plan_watermark(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    forged = copy(plan)
    forged_first = replace(
        plan.watermarks[0],
        expected_instrument_ids=("aqt-security-spy", "forged-security"),
    )
    object.__setattr__(forged, "watermarks", (forged_first, *plan.watermarks[1:]))

    with pytest.raises(DatasetDecodeError, match="exact canonical"):
        reader.read(forged)


def test_plan_and_tape_are_proof_constructed(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    tape = reader.read(plan)

    with pytest.raises(TypeError, match="proof-constructed"):
        ReplayTapePlan()
    with pytest.raises(TypeError, match="proof-constructed"):
        replace(plan, watermarks=plan.watermarks)
    with pytest.raises(TypeError, match="proof-constructed"):
        ManifestReplayTape()
    with pytest.raises(TypeError, match="proof-constructed"):
        replace(tape, bars=tape.bars)


def test_reader_recomputes_arrow_semantics_before_decoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=START,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    original_read = LocalParquetObjectStore.read_table

    def semantically_tampered_read(
        store: LocalParquetObjectStore,
        object_key: str,
        *,
        expected_byte_checksum: str | None = None,
        expected_size_bytes: int | None = None,
    ) -> pa.Table:
        table = original_read(
            store,
            object_key,
            expected_byte_checksum=expected_byte_checksum,
            expected_size_bytes=expected_size_bytes,
        )
        rows = table.to_pylist()
        rows[0]["close"] += Decimal("1")
        return pa.Table.from_pylist(rows, schema=table.schema)

    monkeypatch.setattr(LocalParquetObjectStore, "read_table", semantically_tampered_read)

    with pytest.raises(DatasetDecodeError, match="semantics do not match"):
        reader.read(plan)


def test_empty_selected_tape_replays_as_all_incomplete_and_skipped(tmp_path: Path) -> None:
    _, manifest_id, reader, _ = published_reader(tmp_path)
    plan = reader.build_plan(
        manifest_id=manifest_id,
        event_time_start=END,
        event_time_end=END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )

    tape = reader.read(plan)
    result = replay_manifest_tape(tape)

    assert tape.bars == ()
    assert tape.events == ()
    assert len(result.batches) == 1
    assert result.batches[0].status is MarketBatchStatus.INCOMPLETE
    assert result.skipped_batch_ids == (result.batches[0].batch_id,)
