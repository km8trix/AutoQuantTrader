from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import NoReturn

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from packages.application.manifest_replay import execute_and_seal_manifest_replay
from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.datasets import (
    LocalParquetObjectStore,
    ManifestReplayTape,
    ManifestReplayTapeReader,
)
from packages.domain.replay import LateMarketEvent
from packages.domain.replay_manifest import (
    ReplayManifestDecodeError,
    ReplayRunManifest,
    RuntimePin,
)
from packages.market_data import BarInterval, RawBar
from packages.persistence import replay as replay_persistence
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.replay import (
    SqlReplayRunManifestRepository,
    verify_replay_dataset_catalog,
)
from packages.persistence.schema import (
    calendar_sessions,
    calendar_versions,
    corporate_action_revisions,
    corporate_action_set_members,
    corporate_action_sets,
    data_objects,
    dataset_manifests,
    dataset_partitions,
    market_data_entitlements,
    market_data_sources,
    replay_run_manifests,
    universe_memberships,
    universe_versions,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "market_data" / "phase1_bars.jsonl"
START = datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
END = datetime(2026, 7, 15, 13, 34, tzinfo=UTC)


def _migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/replay.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def _runtime() -> RuntimePin:
    return RuntimePin(
        source_revision="a" * 40,
        dirty_patch_sha256=hashlib.sha256(b"").hexdigest(),
        dependency_lock_sha256=hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        schema_revision=EXPECTED_SCHEMA_REVISION,
        python_version="3.12-test-fixture",
        pyarrow_version="test-fixture",
    )


def _tape(
    tmp_path: Path,
    *,
    decision_lag: timedelta,
    event_time_start: datetime = START,
    event_time_end: datetime = END,
) -> tuple[Engine, ManifestReplayTape]:
    engine = _migrated_engine(tmp_path)
    lake = tmp_path / "lake"
    ingestion = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )
    assert ingestion.manifest_id is not None
    reader = ManifestReplayTapeReader(
        catalog=SqlMarketDataCatalog(engine),
        object_store=LocalParquetObjectStore(lake),
    )
    plan = reader.build_plan(
        manifest_id=ingestion.manifest_id,
        event_time_start=event_time_start,
        event_time_end=event_time_end,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=decision_lag,
    )
    return engine, reader.read(plan)


def _repository(engine: Engine, tmp_path: Path) -> SqlReplayRunManifestRepository:
    return SqlReplayRunManifestRepository(
        engine,
        tape_reader=ManifestReplayTapeReader(
            catalog=SqlMarketDataCatalog(engine),
            object_store=LocalParquetObjectStore(tmp_path / "lake"),
        ),
    )


class _AcceptingPublisher:
    def publish(self, manifest: ReplayRunManifest, tape: ManifestReplayTape) -> bool:
        return type(manifest) is ReplayRunManifest and type(tape) is ManifestReplayTape


class _CatalogOverride(SqlMarketDataCatalog):
    """A substitutable catalog implementation must never become replay authority."""


def _forge_tape_bars(
    tape: ManifestReplayTape,
    bars: tuple[RawBar, ...],
    *,
    events: tuple[object, ...] | None = None,
) -> ManifestReplayTape:
    forged = object.__new__(ManifestReplayTape)
    for field in fields(ManifestReplayTape):
        if field.name == "bars":
            value = bars
        elif field.name == "events" and events is not None:
            value = events
        else:
            value = getattr(tape, field.name)
        object.__setattr__(forged, field.name, value)
    return forged


def test_replay_reader_and_repository_require_exact_shared_dependencies(
    tmp_path: Path,
) -> None:
    engine = _migrated_engine(tmp_path)
    lake = LocalParquetObjectStore(tmp_path / "lake")

    with pytest.raises(ValueError, match="exact trusted SQL catalog"):
        ManifestReplayTapeReader(
            catalog=_CatalogOverride(engine),
            object_store=lake,
        )

    reader = ManifestReplayTapeReader(
        catalog=SqlMarketDataCatalog(engine),
        object_store=lake,
    )
    other_engine = create_database_engine("sqlite+pysqlite:///:memory:")
    with pytest.raises(ValueError, match="share the exact catalog engine"):
        SqlReplayRunManifestRepository(other_engine, tape_reader=reader)


def test_locked_catalog_rederives_plan_from_reference_rows(tmp_path: Path) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    unsealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    forged_plan = replace(
        unsealed.manifest.plan,
        expected_instrument_ids=("aqt-security-spy", "forged-security"),
    )

    with (
        engine.begin() as connection,
        pytest.raises(
            ImmutableFactConflict,
            match="replay plan differs from locked reference facts",
        ),
    ):
        verify_replay_dataset_catalog(
            connection,
            unsealed.manifest.dataset,
            forged_plan,
        )


def test_successful_manifest_replay_is_sealed_once_and_strictly_read_back(
    tmp_path: Path,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    repository = _repository(engine, tmp_path)

    first = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )
    retry = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )

    assert first.first_publication is True
    assert retry.first_publication is False
    assert retry.manifest == first.manifest
    assert first.result.processed_event_ids == tuple(
        event.event_id
        for event in sorted(
            tape.events,
            key=lambda event: (
                event.available_at,
                event.source,
                event.source_sequence is None,
                event.source_sequence or 0,
                event.event_id,
            ),
        )
    )
    assert len(first.result.batches) == 4
    assert len(first.result.complete_batch_ids) == 3
    assert len(first.result.skipped_batch_ids) == 1
    assert first.result.batches[0].events[0].revision == 2
    assert first.result.batches[-1].missing_instrument_ids == ("aqt-security-spy",)
    assert repository.get(first.manifest.run_id) == first.manifest
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 1
    verify_operational_schema(engine, require_phase_zero_facts=False)


def test_late_correction_halts_before_any_success_row_is_written(tmp_path: Path) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(seconds=5))
    repository = _repository(engine, tmp_path)

    with pytest.raises(LateMarketEvent, match="arrived after its watermark"):
        execute_and_seal_manifest_replay(
            tape=tape,
            runtime=_runtime(),
            repository=repository,
        )

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 0


def test_all_missing_skip_window_seals_zero_event_replay(tmp_path: Path) -> None:
    missing_start = END + timedelta(minutes=1)
    missing_end = END + timedelta(minutes=3)
    engine, tape = _tape(
        tmp_path,
        decision_lag=timedelta(minutes=1),
        event_time_start=missing_start,
        event_time_end=missing_end,
    )
    repository = _repository(engine, tmp_path)

    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )

    assert len(tape.plan.watermarks) == 3
    assert tape.bars == ()
    assert tape.events == ()
    assert sealed.result.processed_event_ids == ()
    assert sealed.result.complete_batch_ids == ()
    assert sealed.result.skipped_batch_ids == tuple(
        batch.batch_id for batch in sealed.result.batches
    )
    assert sealed.manifest.processed_event_count == 0
    assert sealed.manifest.complete_batch_count == 0
    assert sealed.manifest.skipped_batch_count == 3
    assert repository.get(sealed.manifest.run_id) == sealed.manifest
    verify_operational_schema(engine, require_phase_zero_facts=False)


def test_conflicting_retry_and_catalog_forgery_leave_original_row_immutable(
    tmp_path: Path,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    repository = _repository(engine, tmp_path)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )

    conflicting = replace(
        sealed.manifest,
        replay_semantic_sha256="0" * 64,
    )
    assert conflicting.input_sha256 == sealed.manifest.input_sha256
    assert conflicting.run_id != sealed.manifest.run_id
    with pytest.raises(ImmutableFactConflict, match="replay outcome fields differ"):
        repository.publish(conflicting, tape)

    forged_dataset = replace(sealed.manifest.dataset, source_kind="recorded_fixture")
    forged = replace(sealed.manifest, dataset=forged_dataset)
    with pytest.raises(ImmutableFactConflict, match="source_kind"):
        repository.publish(forged, tape)

    forged_source_dataset = replace(
        sealed.manifest.dataset,
        source_tape_sha256="9" * 64,
    )
    forged_source = replace(sealed.manifest, dataset=forged_source_dataset)
    with pytest.raises(ImmutableFactConflict, match="source_tape_sha256"):
        repository.publish(forged_source, tape)

    forged_bar = replace(
        tape.bars[0],
        close_price=tape.bars[0].close_price + Decimal("0.01"),
    )
    forged_tape = _forge_tape_bars(tape, (forged_bar, *tape.bars[1:]))
    with pytest.raises(ImmutableFactConflict, match="reader tape proof"):
        repository.publish(sealed.manifest, forged_tape)

    assert repository.get(sealed.manifest.run_id) == sealed.manifest
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 1


def test_coherent_forged_tape_and_matching_manifest_are_not_published(
    tmp_path: Path,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    forged_bar = replace(
        tape.bars[0],
        close_price=tape.bars[0].close_price + Decimal("0.01"),
    )
    forged_event = replace(tape.events[0], close_price=forged_bar.close_price)
    forged_tape = _forge_tape_bars(
        tape,
        (forged_bar, *tape.bars[1:]),
        events=(forged_event, *tape.events[1:]),
    )
    forged_run = execute_and_seal_manifest_replay(
        tape=forged_tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    repository = _repository(engine, tmp_path)

    with pytest.raises(
        ImmutableFactConflict,
        match="supplied tape differs from fresh catalog/object rehydration",
    ):
        repository.publish(forged_run.manifest, forged_tape)

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 0


@pytest.mark.parametrize("tamper", ("delete", "same_length_corruption"))
def test_object_is_revalidated_after_catalog_lock_and_before_sealing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    unpublished = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    repository = _repository(engine, tmp_path)
    object_path = tmp_path / "lake" / tape.partitions[0].object_key
    original_verify = replay_persistence.verify_replay_dataset_catalog

    def verify_then_tamper(*args: object, **kwargs: object) -> object:
        descriptor = original_verify(*args, **kwargs)
        if tamper == "delete":
            object_path.unlink()
        else:
            object_path.write_bytes(b"0" * object_path.stat().st_size)
        return descriptor

    monkeypatch.setattr(
        replay_persistence,
        "verify_replay_dataset_catalog",
        verify_then_tamper,
    )
    with pytest.raises(
        ImmutableFactConflict,
        match="fresh catalog/object rehydration failed",
    ):
        repository.publish(unpublished.manifest, tape)

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 0


def test_publish_uses_the_locked_descriptor_without_a_second_catalog_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    unpublished = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    repository = _repository(engine, tmp_path)

    def forbidden_unlocked_lookup(*_args: object, **_kwargs: object) -> object:
        pytest.fail("replay publication must consume the locked catalog descriptor")

    monkeypatch.setattr(
        SqlMarketDataCatalog,
        "manifest_objects",
        forbidden_unlocked_lookup,
    )
    assert repository.publish(unpublished.manifest, tape) is True


def test_publish_transaction_rolls_back_insert_when_strict_readback_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    unpublished = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    repository = _repository(engine, tmp_path)

    def reject_readback(_: object) -> NoReturn:
        raise ImmutableFactConflict("forced strict read-back failure")

    monkeypatch.setattr(replay_persistence, "_decode_row", reject_readback)
    with pytest.raises(ImmutableFactConflict, match="forced strict read-back"):
        repository.publish(unpublished.manifest, tape)

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 0


def test_publish_rejects_forged_non_adapter_engine_contract_without_writing(
    tmp_path: Path,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    unpublished = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=_AcceptingPublisher(),
    )
    forged_engine = replace(
        unpublished.manifest.engine,
        replay_contract_version="forged-replay-contract-v0",
    )
    forged_manifest = replace(unpublished.manifest, engine=forged_engine)
    repository = _repository(engine, tmp_path)

    with pytest.raises(ImmutableFactConflict, match="replay_contract_version"):
        repository.publish(forged_manifest, tape)

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(replay_run_manifests)) == 0


@pytest.mark.parametrize(
    "tamper",
    (
        "calendar_hash",
        "calendar_hash_version",
        "universe_hash",
        "universe_hash_version",
        "corporate_action_hash",
        "corporate_action_hash_version",
        "source_kind",
        "manifest_schema",
        "revision_policy",
        "partition_schema",
        "partition_checksum_version",
        "object_checksum_version",
        "object_key",
        "object_format",
        "object_size",
        "partition_event_time_start",
        "partition_event_time_end",
        "partition_available_at_start",
        "partition_available_at_end",
        "calendar_session",
        "universe_membership",
        "corporate_action_fact",
    ),
)
def test_catalog_tamper_fails_repository_read_and_operational_readiness(
    tmp_path: Path,
    tamper: str,
) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    repository = _repository(engine, tmp_path)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )
    dataset = sealed.manifest.dataset

    with engine.begin() as connection:
        if tamper == "calendar_hash":
            connection.execute(
                sa.update(calendar_versions)
                .where(calendar_versions.c.calendar_version == dataset.calendar_version)
                .values(content_hash="b" * 64)
            )
        elif tamper == "calendar_hash_version":
            connection.execute(
                sa.update(calendar_versions)
                .where(calendar_versions.c.calendar_version == dataset.calendar_version)
                .values(content_hash_version="input-v1")
            )
        elif tamper == "universe_hash":
            connection.execute(
                sa.update(universe_versions)
                .where(universe_versions.c.universe_version == dataset.universe_version)
                .values(content_hash="c" * 64)
            )
        elif tamper == "universe_hash_version":
            connection.execute(
                sa.update(universe_versions)
                .where(universe_versions.c.universe_version == dataset.universe_version)
                .values(content_hash_version="input-v1")
            )
        elif tamper == "corporate_action_hash":
            connection.execute(
                sa.update(corporate_action_sets)
                .where(
                    corporate_action_sets.c.corporate_action_version
                    == dataset.corporate_action_version
                )
                .values(content_hash="d" * 64)
            )
        elif tamper == "corporate_action_hash_version":
            connection.execute(
                sa.update(corporate_action_sets)
                .where(
                    corporate_action_sets.c.corporate_action_version
                    == dataset.corporate_action_version
                )
                .values(content_hash_version="input-v1")
            )
        elif tamper == "source_kind":
            connection.execute(
                sa.update(market_data_sources)
                .where(market_data_sources.c.source_id == dataset.source_id)
                .values(kind="recorded_fixture")
            )
        elif tamper == "manifest_schema":
            connection.execute(
                sa.update(dataset_manifests)
                .where(dataset_manifests.c.manifest_id == dataset.manifest_id)
                .values(schema_version="forged-v2")
            )
        elif tamper == "revision_policy":
            connection.execute(
                sa.update(dataset_manifests)
                .where(dataset_manifests.c.manifest_id == dataset.manifest_id)
                .values(revision_policy="first_seen")
            )
        elif tamper == "partition_schema":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(schema_version="forged-v2")
            )
        elif tamper == "partition_checksum_version":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(semantic_checksum_version="input-v1")
            )
        elif tamper == "object_checksum_version":
            connection.execute(
                sa.update(data_objects)
                .where(data_objects.c.object_id == dataset.partitions[0].object_id)
                .values(semantic_checksum_version="input-v1")
            )
        elif tamper == "object_key":
            connection.execute(
                sa.update(data_objects)
                .where(data_objects.c.object_id == dataset.partitions[0].object_id)
                .values(object_key="normalized/forged-object.parquet")
            )
        elif tamper == "object_format":
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                sa.update(data_objects)
                .where(data_objects.c.object_id == dataset.partitions[0].object_id)
                .values(format="csv")
            )
            connection.exec_driver_sql("PRAGMA ignore_check_constraints = OFF")
        elif tamper == "object_size":
            connection.execute(
                sa.update(data_objects)
                .where(data_objects.c.object_id == dataset.partitions[0].object_id)
                .values(size_bytes=dataset.partitions[0].size_bytes + 1)
            )
        elif tamper == "partition_event_time_start":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(event_time_start=START - timedelta(days=1))
            )
        elif tamper == "partition_event_time_end":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(event_time_end=END + timedelta(days=1))
            )
        elif tamper == "partition_available_at_start":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(available_at_start=START - timedelta(days=1))
            )
        elif tamper == "partition_available_at_end":
            connection.execute(
                sa.update(dataset_partitions)
                .where(dataset_partitions.c.partition_id == dataset.partitions[0].partition_id)
                .values(available_at_end=END + timedelta(days=1))
            )
        elif tamper == "calendar_session":
            connection.execute(
                sa.update(calendar_sessions)
                .where(
                    calendar_sessions.c.calendar_version == dataset.calendar_version,
                    calendar_sessions.c.session_label == "2026-07-15",
                )
                .values(half_day=True)
            )
        elif tamper == "universe_membership":
            connection.execute(
                sa.update(universe_memberships)
                .where(universe_memberships.c.universe_version == dataset.universe_version)
                .values(available_at=START)
            )
        else:
            action_revision_id = connection.scalar(
                sa.select(corporate_action_set_members.c.action_revision_id)
                .where(
                    corporate_action_set_members.c.corporate_action_version
                    == dataset.corporate_action_version
                )
                .order_by(corporate_action_set_members.c.ordinal)
                .limit(1)
            )
            assert isinstance(action_revision_id, str)
            connection.execute(
                sa.update(corporate_action_revisions)
                .where(corporate_action_revisions.c.action_revision_id == action_revision_id)
                .values(available_at=START)
            )

    with pytest.raises(ImmutableFactConflict, match="catalog"):
        repository.publish(sealed.manifest, tape)
    with pytest.raises(ImmutableFactConflict, match="catalog"):
        repository.get(sealed.manifest.run_id)
    with pytest.raises(DatabaseSchemaNotReady, match="catalog verification"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_mixed_fixture_and_active_entitlements_fail_closed(tmp_path: Path) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    repository = _repository(engine, tmp_path)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(market_data_entitlements).values(
                entitlement_id="mixed-active-entitlement",
                source_id=sealed.manifest.dataset.source_id,
                status="active",
                scope="forged mixed authority",
                effective_from=START,
                effective_to=None,
                terms_digest="e" * 64,
                observed_at=START,
            )
        )

    with pytest.raises(ImmutableFactConflict, match="exclusively fixture-only"):
        repository.get(sealed.manifest.run_id)
    with pytest.raises(DatabaseSchemaNotReady, match="catalog verification"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_payload_tamper_fails_strict_read_and_operational_readiness(tmp_path: Path) -> None:
    engine, tape = _tape(tmp_path, decision_lag=timedelta(minutes=1))
    repository = _repository(engine, tmp_path)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=repository,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(replay_run_manifests)
            .where(replay_run_manifests.c.run_id == sealed.manifest.run_id)
            .values(manifest_payload=sealed.manifest.canonical_json + " ")
        )

    with pytest.raises(ReplayManifestDecodeError, match="not canonical"):
        repository.get(sealed.manifest.run_id)
    with pytest.raises(DatabaseSchemaNotReady, match="payload verification"):
        verify_operational_schema(engine, require_phase_zero_facts=False)
