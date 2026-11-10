from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from apps.api.config import Settings
from apps.api.main import create_app
from packages.adapters.market_data.recorded import (
    RecordedHistoricalBarSource,
    RecordedJsonlBarSource,
)
from packages.adapters.market_data.reference_fixture import admission_profile, reference_fixture
from packages.application import market_data_ingestion
from packages.application.market_data_ingestion import (
    _LEGACY_INTEGRITY_CONTRACT,
    HistoricalSourceProfileMismatch,
    ingest_historical_source,
    ingest_recorded_fixture,
)
from packages.datasets import (
    ARROW_SEMANTIC_CHECKSUM_VERSION,
    INPUT_REFERENCE_HASH_VERSION,
    INPUT_SEMANTIC_CHECKSUM_VERSION,
    PERSISTED_REFERENCE_HASH_VERSION,
    LocalParquetObjectStore,
    ManifestBarReader,
)
from packages.market_data import RevisionPolicy, normalize_records, select_as_of
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.schema import (
    calendar_versions,
    corporate_action_sets,
    data_objects,
    data_quality_issues,
    dataset_manifest_partitions,
    dataset_manifests,
    dataset_partitions,
    ingestion_jobs,
    market_data_admission_checks,
    market_data_admission_profiles,
    market_data_admission_runs,
    partition_quarantines,
    universe_versions,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "market_data" / "phase1_bars.jsonl"


def migrated_engine(tmp_path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/market-data.sqlite")
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option(
        "sqlalchemy.url",
        engine.url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    command.upgrade(config, "head")
    return engine


def recorded_fixture_source(path: Path = FIXTURE) -> RecordedHistoricalBarSource:
    fixture = reference_fixture()
    return RecordedHistoricalBarSource(
        path,
        profile=admission_profile(),
        security_master=fixture.security_master,
        calendar=fixture.calendar,
        corporate_actions=fixture.corporate_actions,
        entitlement=fixture.entitlement,
    )


def test_fixture_ingestion_is_content_addressed_idempotent_and_quarantines(
    tmp_path: Path,
) -> None:
    engine = migrated_engine(tmp_path)
    lake = tmp_path / "lake"

    first = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )
    second = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )

    assert first.first_publication is True
    assert second.first_publication is False
    assert first.job_id == second.job_id
    assert first.manifest_id == second.manifest_id
    assert first.partition_checksums == second.partition_checksums
    assert first.source_record_count == 5
    assert first.normalized_record_count == 4
    assert first.quarantined_record_count == 1
    assert first.admission_status == "blocked"
    assert first.admission_run_id is not None
    with engine.connect() as connection:
        counts = {
            "jobs": connection.scalar(sa.select(sa.func.count()).select_from(ingestion_jobs)),
            "objects": connection.scalar(sa.select(sa.func.count()).select_from(data_objects)),
            "partitions": connection.scalar(
                sa.select(sa.func.count()).select_from(dataset_partitions)
            ),
            "manifests": connection.scalar(
                sa.select(sa.func.count()).select_from(dataset_manifests)
            ),
            "members": connection.scalar(
                sa.select(sa.func.count()).select_from(dataset_manifest_partitions)
            ),
            "issues": connection.scalar(
                sa.select(sa.func.count()).select_from(data_quality_issues)
            ),
            "quarantines": connection.scalar(
                sa.select(sa.func.count()).select_from(partition_quarantines)
            ),
            "admission_profiles": connection.scalar(
                sa.select(sa.func.count()).select_from(market_data_admission_profiles)
            ),
            "admission_runs": connection.scalar(
                sa.select(sa.func.count()).select_from(market_data_admission_runs)
            ),
            "admission_checks": connection.scalar(
                sa.select(sa.func.count()).select_from(market_data_admission_checks)
            ),
        }
        object_rows = connection.execute(sa.select(data_objects)).mappings().all()
        normalized_key = connection.scalar(
            sa.select(data_objects.c.object_key)
            .join(dataset_partitions, dataset_partitions.c.object_id == data_objects.c.object_id)
            .where(dataset_partitions.c.layer == "normalized")
        )
        manifest_schema_version = connection.scalar(sa.select(dataset_manifests.c.schema_version))
        object_checksum_versions = set(
            connection.scalars(sa.select(data_objects.c.semantic_checksum_version))
        )
        partition_checksum_versions = set(
            connection.scalars(sa.select(dataset_partitions.c.semantic_checksum_version))
        )
        reference_hash_versions = {
            connection.scalar(sa.select(calendar_versions.c.content_hash_version)),
            connection.scalar(sa.select(universe_versions.c.content_hash_version)),
            connection.scalar(sa.select(corporate_action_sets.c.content_hash_version)),
        }
    assert counts == {
        "jobs": 1,
        "objects": 3,
        "partitions": 3,
        "manifests": 1,
        "members": 1,
        "issues": 1,
        "quarantines": 1,
        "admission_profiles": 1,
        "admission_runs": 1,
        "admission_checks": 18,
    }
    assert manifest_schema_version == "raw-bar-v2"
    assert object_checksum_versions == {ARROW_SEMANTIC_CHECKSUM_VERSION}
    assert partition_checksum_versions == {ARROW_SEMANTIC_CHECKSUM_VERSION}
    assert reference_hash_versions == {PERSISTED_REFERENCE_HASH_VERSION}
    for row in object_rows:
        object_path = lake / str(row["object_key"])
        assert object_path.is_file()
        assert hashlib.sha256(object_path.read_bytes()).hexdigest() == row["byte_checksum"]
    assert isinstance(normalized_key, str)
    normalized_table = LocalParquetObjectStore(lake).read_table(normalized_key)
    assert normalized_table.num_rows == 4
    assert sorted(normalized_table.column("revision").to_pylist()) == [1, 1, 1, 2]
    assert set(normalized_table.column("price_basis").to_pylist()) == {"raw"}
    assert first.manifest_id is not None
    reader = ManifestBarReader(
        catalog=SqlMarketDataCatalog(engine),
        object_store=LocalParquetObjectStore(lake),
    )
    before_correction = reader.bars_as_of(
        manifest_id=first.manifest_id,
        as_of=datetime(2026, 7, 15, 13, 31, 59, tzinfo=UTC),
    )
    after_correction = reader.bars_as_of(
        manifest_id=first.manifest_id,
        as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
    )
    assert before_correction[0].revision == 1
    assert before_correction[0].close_price == Decimal("100.80")
    assert after_correction[0].revision == 2
    assert after_correction[0].close_price == Decimal("100.90")
    verify_operational_schema(engine, require_phase_zero_facts=False)


def test_migrated_legacy_fixture_rerun_reconstructs_the_complete_v1_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_engine(tmp_path)
    lake = tmp_path / "legacy-lake"

    with monkeypatch.context() as migration_seed:
        migration_seed.setattr(
            market_data_ingestion,
            "_select_integrity_contract",
            lambda catalog, bundle, *, policy: market_data_ingestion._SelectedIntegrityContract(
                _LEGACY_INTEGRITY_CONTRACT
            ),
        )
        legacy = ingest_recorded_fixture(
            engine=engine,
            data_lake_path=lake,
            source_path=FIXTURE,
        )
    retry = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )

    assert legacy.first_publication is True
    assert retry.first_publication is False
    assert legacy.job_id == retry.job_id
    assert legacy.job_id == "f76fbbd8b03fff4ae9b8696f9884ab470ca91fb2dd3f6ac8e325e777669dfb0f"
    assert legacy.manifest_id == retry.manifest_id
    assert legacy.partition_checksums == retry.partition_checksums
    assert legacy.admission_run_id == retry.admission_run_id
    assert legacy.admission_status == retry.admission_status == "blocked"

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(ingestion_jobs)) == 1
        assert connection.scalar(sa.select(sa.func.count()).select_from(dataset_manifests)) == 1
        assert connection.scalar(sa.select(sa.func.count()).select_from(data_objects)) == 3
        assert connection.scalar(sa.select(sa.func.count()).select_from(dataset_partitions)) == 3
        assert set(connection.scalars(sa.select(dataset_manifests.c.schema_version))) == {
            "raw-bar-v1"
        }
        assert set(connection.scalars(sa.select(data_objects.c.semantic_checksum_version))) == {
            INPUT_SEMANTIC_CHECKSUM_VERSION
        }
        assert set(
            connection.scalars(sa.select(dataset_partitions.c.semantic_checksum_version))
        ) == {INPUT_SEMANTIC_CHECKSUM_VERSION}
        assert {
            connection.scalar(sa.select(calendar_versions.c.content_hash_version)),
            connection.scalar(sa.select(universe_versions.c.content_hash_version)),
            connection.scalar(sa.select(corporate_action_sets.c.content_hash_version)),
        } == {INPUT_REFERENCE_HASH_VERSION}

    assert legacy.manifest_id is not None
    descriptor = SqlMarketDataCatalog(engine).manifest_objects(legacy.manifest_id)
    assert descriptor.schema_version == "raw-bar-v1"
    assert descriptor.row_count == legacy.normalized_record_count


def test_legacy_retry_rejects_a_different_object_receipt_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_engine(tmp_path)
    lake = tmp_path / "legacy-receipt-lake"
    with monkeypatch.context() as migration_seed:
        migration_seed.setattr(
            market_data_ingestion,
            "_select_integrity_contract",
            lambda catalog, bundle, *, policy: market_data_ingestion._SelectedIntegrityContract(
                _LEGACY_INTEGRITY_CONTRACT
            ),
        )
        legacy = ingest_recorded_fixture(
            engine=engine,
            data_lake_path=lake,
            source_path=FIXTURE,
        )
    assert legacy.manifest_id is not None
    original_manifest_objects = SqlMarketDataCatalog.manifest_objects

    def different_receipt(
        catalog: SqlMarketDataCatalog,
        manifest_id: str,
    ) -> object:
        descriptor = original_manifest_objects(catalog, manifest_id)
        partition = replace(
            descriptor.partitions[0],
            size_bytes=descriptor.partitions[0].size_bytes + 1,
        )
        return replace(descriptor, partitions=(partition,))

    def forbidden_publish(*_args: object, **_kwargs: object) -> bool:
        pytest.fail("a mismatched legacy receipt must fail before catalog publication")

    monkeypatch.setattr(SqlMarketDataCatalog, "manifest_objects", different_receipt)
    monkeypatch.setattr(SqlMarketDataCatalog, "publish", forbidden_publish)
    with pytest.raises(
        ImmutableFactConflict,
        match="differs from the reconstructed object receipt",
    ):
        ingest_recorded_fixture(
            engine=engine,
            data_lake_path=lake,
            source_path=FIXTURE,
        )


def test_generic_historical_source_preserves_recorded_fixture_behavior(tmp_path: Path) -> None:
    engine = migrated_engine(tmp_path)
    lake = tmp_path / "lake"

    generic = ingest_historical_source(
        engine=engine,
        data_lake_path=lake,
        source=recorded_fixture_source(),
    )
    compatibility_wrapper = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=FIXTURE,
    )

    assert generic.first_publication is True
    assert compatibility_wrapper.first_publication is False
    assert generic.job_id == compatibility_wrapper.job_id
    assert generic.manifest_id == compatibility_wrapper.manifest_id
    assert generic.partition_checksums == compatibility_wrapper.partition_checksums
    assert generic.source_record_count == compatibility_wrapper.source_record_count == 5
    assert generic.normalized_record_count == compatibility_wrapper.normalized_record_count == 4
    assert generic.quarantined_record_count == compatibility_wrapper.quarantined_record_count == 1


def test_mixed_source_bundle_is_rejected_before_storage_or_catalog_write(
    tmp_path: Path,
) -> None:
    engine = migrated_engine(tmp_path)
    mixed_source_path = tmp_path / "mixed-source.jsonl"
    payload = FIXTURE.read_text(encoding="utf-8").replace(
        '"source_id":"synthetic-pit-bars-v1"',
        '"source_id":"unexpected-source"',
        1,
    )
    mixed_source_path.write_text(payload, encoding="utf-8")

    with pytest.raises(
        HistoricalSourceProfileMismatch,
        match="unexpected-source",
    ):
        ingest_historical_source(
            engine=engine,
            data_lake_path=tmp_path / "lake",
            source=recorded_fixture_source(mixed_source_path),
        )

    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(ingestion_jobs)) == 0
        assert connection.scalar(sa.select(sa.func.count()).select_from(data_objects)) == 0
    assert not (tmp_path / "lake").exists()


def test_correction_is_visible_only_after_its_availability_time() -> None:
    fixture = reference_fixture()
    normalized = normalize_records(
        RecordedJsonlBarSource(FIXTURE).records(),
        calendar=fixture.calendar,
        security_master=fixture.security_master,
    )

    before = select_as_of(
        normalized.bars,
        as_of=datetime(2026, 7, 15, 13, 31, 59, tzinfo=UTC),
        policy=RevisionPolicy.REVISED_AS_OF,
    )
    after = select_as_of(
        normalized.bars,
        as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        policy=RevisionPolicy.REVISED_AS_OF,
    )
    first_seen = select_as_of(
        normalized.bars,
        as_of=datetime(2026, 7, 15, 13, 40, tzinfo=UTC),
        policy=RevisionPolicy.FIRST_SEEN,
    )

    assert len(before) == 1
    assert before[0].revision == 1
    assert before[0].close_price == Decimal("100.80")
    assert after[0].revision == 2
    assert after[0].close_price == Decimal("100.90")
    assert first_seen[0].revision == 1
    assert first_seen[0].close_price == Decimal("100.80")


def test_data_catalog_and_quality_browser_contracts(tmp_path: Path) -> None:
    engine = migrated_engine(tmp_path)
    outcome = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=tmp_path / "lake",
        source_path=FIXTURE,
    )
    client = TestClient(create_app(Settings(), engine=engine))

    catalog_response = client.get("/api/v1/data/catalog")
    quality_response = client.get("/api/v1/data/quality")

    assert catalog_response.status_code == 200
    catalog = catalog_response.json()
    assert catalog["source"]["kind"] == "synthetic_fixture"
    assert catalog["source"]["licensed"] is False
    assert catalog["source"]["entitlement_status"] == "fixture_only"
    assert catalog["jobs"][0]["job_id"] == outcome.job_id
    assert catalog["manifests"][0]["manifest_id"] == outcome.manifest_id
    assert catalog["manifests"][0]["price_basis"] == "raw"
    assert catalog["manifests"][0]["partitions"][0]["object_key"].startswith("normalized/sha256/")
    assert len(catalog["instruments"]) == 3
    assert any(instrument["status"] == "delisted" for instrument in catalog["instruments"])
    assert {action["action_type"] for action in catalog["corporate_actions"]} == {
        "cash_dividend",
        "delisting",
        "split",
        "symbol_change",
    }
    assert catalog["entitlements"] == [
        {
            "source_id": "synthetic-pit-bars-v1",
            "feed": "recorded-jsonl",
            "licensed": False,
            "status": "fixture_only",
            "scope": "Synthetic records for local contract testing only",
            "verified_at": "2026-07-15T14:00:00Z",
        }
    ]
    assert len(catalog["admissions"]) == 1
    admission = catalog["admissions"][0]
    assert admission["status"] == "blocked"
    assert admission["source_id"] == "synthetic-pit-bars-v1"
    assert admission["manifest_id"] == outcome.manifest_id
    assert admission["adapter_type"] == "recorded_jsonl"
    assert admission["identifier_authority"] == "autoquant-synthetic-v1"
    assert admission["required_symbols"] == ["SPY"]
    assert admission["passed_check_count"] == 14
    assert admission["failed_check_count"] == 3
    assert admission["pending_check_count"] == 1
    assert any(
        check["code"] == "source_kind" and check["status"] == "failed"
        for check in admission["checks"]
    )
    assert any(
        check["code"] == "independent_approval" and check["status"] == "pending"
        for check in admission["checks"]
    )

    assert quality_response.status_code == 200
    quality = quality_response.json()
    assert quality["issues"][0]["code"] == "ohlc_invalid"
    assert quality["issues"][0]["quarantined"] is True
    assert quality["quarantine"][0]["row_count"] == 1


def test_empty_catalog_is_an_honest_successful_read(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(), engine=migrated_engine(tmp_path)))

    catalog = client.get("/api/v1/data/catalog")
    quality = client.get("/api/v1/data/quality")

    assert catalog.status_code == 200
    assert catalog.json()["source"] is None
    assert catalog.json()["jobs"] == []
    assert catalog.json()["manifests"] == []
    assert catalog.json()["admissions"] == []
    assert quality.status_code == 200
    assert quality.json()["issues"] == []
    assert quality.json()["quarantine"] == []


def test_readiness_rejects_an_admitted_status_forged_onto_a_fixture(tmp_path: Path) -> None:
    engine = migrated_engine(tmp_path)
    ingest_recorded_fixture(
        engine=engine,
        data_lake_path=tmp_path / "lake",
        source_path=FIXTURE,
    )
    reviewed_at = datetime(2026, 7, 15, 14, 1, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            sa.update(market_data_admission_checks).values(
                status="passed",
                evidence_digest="f" * 64,
            )
        )
        connection.execute(
            sa.update(market_data_admission_runs).values(
                status="admitted",
                reviewed_at=reviewed_at,
                reviewed_by="independent-reviewer",
                review_decision="approved",
                passed_check_count=18,
                failed_check_count=0,
                pending_check_count=0,
            )
        )

    with pytest.raises(
        DatabaseSchemaNotReady,
        match="point-in-time data catalog integrity verification failed",
    ):
        verify_operational_schema(engine, require_phase_zero_facts=False)
